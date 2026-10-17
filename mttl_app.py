# -*- coding: utf-8 -*-
"""
MTTL-W01 Smart Home Controller  -  البيت الذكي: تحكم محلي في المشتركات الكورية
Multiple strips, timers, schedules, activity log.
Pure Python 3.8+ standard library. No pip installs needed.

Protocol (verified by the community, see github.com/AmrEmad0/MTTL-W01_APP
and github.com/HanyArnous/power_strip):

  Setup  : laptop joins TONLY_TAP_xxxx  (password usually LGU_xxxx)
           TCP 192.168.1.1:30300, one line per connection, CRLF:
             up:ip:<laptop home IPv4>      -> up:ip:ip_ok
             up:connect:<ssid>:<password>  -> up:connect:connect_ok
             up:reboot:0
  Runtime: strip dials laptop TCP 10086
             strip -> up:bootinfo:<model>;<MAC>;<MAC>;<fw>;connect
             app   -> up:getinfo:all        (telemetry, 4 records)
             app   -> up:onoff:<1-4>:<on|off>
             strip -> up:onoff:N:on / up:event:onoff:N:on
"""
import collections
import datetime
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from xml.sax.saxutils import escape as xml_escape

DEVICE_PORT = 10086
WEB_PORT = int(os.environ.get("MTTL_WEB_PORT", "8080"))
SETUP_PORT = int(os.environ.get("MTTL_SETUP_PORT", "30300"))
SETUP_HOSTS = os.environ.get("MTTL_SETUP_HOSTS", "192.168.1.1,192.168.4.1").split(",")
POLL_SECONDS = 4
IS_WIN = os.name == "nt"
BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE, "mttl_config.json")   # old format, imported once
DB_PATH = os.path.join(BASE, "mttl.db")
TYPES = ("tv", "heater", "ac", "fridge", "washer", "kettle", "lamp", "fan",
         "router", "charger", "pc", "pump", "other")

BOOT_RE = re.compile(r"^up:bootinfo:([^;]+);([0-9A-Fa-f]{12});([0-9A-Fa-f]{12});([^;]+);connect$")
GETINFO_RE = re.compile(
    r"(?P<ch>[1-5]):(?P<timer>-?\d+);(?P<relay>on|off);(?P<standby>-?\d+);"
    r"(?P<ovl>[^;:]+);(?P<ovh>[^;:]+);(?P<power>-?\d+);"
    r"(?P<energy>[0-9A-Fa-f]{8});(?P<e2>[0-9A-Fa-f]{8});(?P<e3>[0-9A-Fa-f]{8});"
    r"(?P<sbflag>[^;:]+);(?P<event>[0-9A-Fa-f]{2});(?P<temp>-?\d+)", re.I)
ONOFF_RE = re.compile(r"^up:(?:event:)?onoff:([0-4]):(on|off)$", re.I)
SETUP_PREFIXES = ("TONLY_TAP_", "ONLY_TAP_")


def log(*a):
    print(time.strftime("[%H:%M:%S]"), *a, flush=True)


# ---------------------------------------------------------------- storage (SQLite: mttl.db)
SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS strips (
    mac TEXT PRIMARY KEY, label TEXT, ip TEXT, fw TEXT, last_seen REAL, added_at REAL);
CREATE TABLE IF NOT EXISTS outlets (
    mac TEXT, n INTEGER, name TEXT, type TEXT, room TEXT, last_energy_wh INTEGER,
    PRIMARY KEY (mac, n));
CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY, name TEXT, action TEXT, time TEXT, enabled INTEGER, data TEXT);
CREATE TABLE IF NOT EXISTS timers (
    mac TEXT, n INTEGER, action TEXT, at REAL, PRIMARY KEY (mac, n));
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, text TEXT);
CREATE TABLE IF NOT EXISTS energy_daily (
    day TEXT, mac TEXT, n INTEGER, wh REAL, PRIMARY KEY (day, mac, n));
CREATE TABLE IF NOT EXISTS energy_hourly (
    hour TEXT, mac TEXT, n INTEGER, wh REAL, PRIMARY KEY (hour, mac, n));
"""
_db_lock = threading.RLock()
DB = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
DB.execute("PRAGMA journal_mode=WAL")
DB.executescript(SCHEMA)
try:
    DB.execute("ALTER TABLE outlets ADD COLUMN autooff TEXT")
except sqlite3.OperationalError:
    pass  # column already there
_LIST_KEYS = ("strips", "schedules", "timers", "names", "_migrate")


def db(sql, args=()):
    with _db_lock:
        return DB.execute(sql, args).fetchall()


def load_cfg():
    rows = db("SELECT key, value FROM settings")
    if not rows and not db("SELECT 1 FROM strips LIMIT 1") and os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                c = json.load(f)
            c["_migrate"] = True
            return c
        except Exception:
            pass
    cfg = {k: json.loads(v) for k, v in rows}
    strips = {}
    for mac, label, ip, fw, seen in db("SELECT mac, label, ip, fw, last_seen FROM strips"):
        strips[mac] = {"label": label or "", "ip": ip or "", "fw": fw or "", "last_seen": seen,
                       "names": {}, "types": {}, "rooms": {}, "autooff": {}}
    for mac, n, name, typ, room, ao in db("SELECT mac, n, name, type, room, autooff FROM outlets"):
        if mac in strips:
            for key, val in (("names", name), ("types", typ), ("rooms", room)):
                if val:
                    strips[mac][key][str(n)] = val
            if ao:
                strips[mac]["autooff"][str(n)] = json.loads(ao)
    cfg["strips"] = strips
    cfg["schedules"] = [json.loads(d) for (d,) in db("SELECT data FROM schedules ORDER BY rowid")]
    cfg["timers"] = {"%s:%d" % (m, n): {"action": a, "at": at}
                     for m, n, a, at in db("SELECT mac, n, action, at FROM timers")}
    return cfg


CFG = load_cfg()


def save_cfg():
    """Write the in-memory home model to mttl.db in one transaction."""
    with _db_lock:
        DB.execute("BEGIN")
        try:
            for k, v in CFG.items():
                if k not in _LIST_KEYS:
                    DB.execute("INSERT INTO settings(key, value) VALUES(?, ?) "
                               "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                               (k, json.dumps(v, ensure_ascii=False)))
            strips = CFG.get("strips", {})
            marks = ",".join("?" * len(strips))
            for table in ("strips", "outlets"):
                DB.execute("DELETE FROM %s WHERE mac NOT IN (%s)" % (table, marks) if strips
                           else "DELETE FROM %s" % table, tuple(strips))
            for mac, k in strips.items():
                DB.execute("INSERT INTO strips(mac, label, ip, fw, last_seen, added_at) VALUES(?,?,?,?,?,?) "
                           "ON CONFLICT(mac) DO UPDATE SET label=excluded.label, ip=excluded.ip, "
                           "fw=excluded.fw, last_seen=excluded.last_seen",
                           (mac, k.get("label", ""), k.get("ip", ""), k.get("fw", ""),
                            k.get("last_seen"), time.time()))
                for n in range(1, 5):
                    ao = k.get("autooff", {}).get(str(n))
                    DB.execute("INSERT INTO outlets(mac, n, name, type, room, autooff) VALUES(?,?,?,?,?,?) "
                               "ON CONFLICT(mac, n) DO UPDATE SET name=excluded.name, "
                               "type=excluded.type, room=excluded.room, autooff=excluded.autooff",
                               (mac, n, k.get("names", {}).get(str(n), ""),
                                k.get("types", {}).get(str(n), ""), k.get("rooms", {}).get(str(n), ""),
                                json.dumps(ao) if ao else None))
            DB.execute("DELETE FROM schedules")
            for r in CFG.get("schedules", []):
                DB.execute("INSERT INTO schedules(id, name, action, time, enabled, data) VALUES(?,?,?,?,?,?)",
                           (r["id"], r.get("name", ""), r["action"], r["time"], int(r.get("enabled", True)),
                            json.dumps(r, ensure_ascii=False)))
            DB.execute("DELETE FROM timers")
            for key, t in CFG.get("timers", {}).items():
                mac, n = key.rsplit(":", 1)
                DB.execute("INSERT INTO timers(mac, n, action, at) VALUES(?,?,?,?)", (mac, int(n), t["action"], t["at"]))
            DB.execute("COMMIT")
        except Exception:
            DB.execute("ROLLBACK")
            raise


def tr(ar, en):
    """Pick the UI language for server-side messages (events, errors, setup steps)."""
    return en if CFG.get("lang") == "en" else ar


# ---------------------------------------------------------------- network helpers
def current_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def run(cmd, timeout=20):
    kw = {}
    if IS_WIN:
        kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout, **kw)
        raw = out.stdout + out.stderr
    except Exception as e:
        return "", 1, str(e)
    for enc in ("utf-8", "mbcs" if IS_WIN else "utf-8", "cp1256", "latin-1"):
        try:
            return raw.decode(enc), out.returncode, ""
        except Exception:
            continue
    return raw.decode("latin-1", "ignore"), out.returncode, ""


def wifi_current_ssid():
    if not IS_WIN:
        return ""
    text, _, _ = run(["netsh", "wlan", "show", "interfaces"])
    m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", text, re.M)
    return m.group(1) if m else ""


def wifi_scan():
    if not IS_WIN:
        return []
    text, _, _ = run(["netsh", "wlan", "show", "networks"])
    names = re.findall(r"^SSID \d+\s*:\s*(.*?)\s*$", text, re.M)
    return [n for n in names if n]


def setup_networks():
    return [n for n in wifi_scan() if n.upper().startswith(SETUP_PREFIXES)]


def setup_ap_password(ssid):
    return "LGU_" + ssid.rsplit("_", 1)[-1]


def wifi_connect_profile(ssid, password=None):
    """Create a temporary Windows Wi-Fi profile and connect to it."""
    if password:
        sec = ("<authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption>"
               "<useOneX>false</useOneX></authEncryption><sharedKey><keyType>passPhrase</keyType>"
               "<protected>false</protected><keyMaterial>%s</keyMaterial></sharedKey>" % xml_escape(password))
    else:
        sec = ("<authEncryption><authentication>open</authentication><encryption>none</encryption>"
               "<useOneX>false</useOneX></authEncryption>")
    xml = ('<?xml version="1.0"?><WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">'
           "<name>%s</name><SSIDConfig><SSID><name>%s</name></SSID></SSIDConfig>"
           "<connectionType>ESS</connectionType><connectionMode>manual</connectionMode>"
           "<MSM><security>%s</security></MSM></WLANProfile>") % (xml_escape(ssid), xml_escape(ssid), sec)
    path = os.path.join(tempfile.gettempdir(), "mttl_profile.xml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(xml)
    run(["netsh", "wlan", "add", "profile", "filename=" + path, "user=current"])
    try:
        os.remove(path)
    except Exception:
        pass
    run(["netsh", "wlan", "connect", "name=" + ssid, "ssid=" + ssid])


def wifi_connect_existing(ssid):
    run(["netsh", "wlan", "connect", "name=" + ssid])


def setup_reachable():
    for h in SETUP_HOSTS:
        try:
            with socket.create_connection((h.strip(), SETUP_PORT), timeout=2):
                return h.strip()
        except OSError:
            continue
    return None


def setup_command(host, cmd, expect, timeout=7.0):
    with socket.create_connection((host, SETUP_PORT), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((cmd + "\r\n").encode("utf-8"))
        if not expect:
            return ""
        buf, deadline = b"", time.monotonic() + timeout
        while b"\n" not in buf and time.monotonic() < deadline:
            try:
                chunk = s.recv(1024)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    text = buf.replace(b"\x00", b"").decode("utf-8", "replace").strip()
    if expect not in text:
        raise RuntimeError(tr("المشترك رد بـ %r بدل %r", "The strip answered %r instead of %r") % (text, expect))
    return text


# ---------------------------------------------------------------- persistent home model
LOCK = threading.RLock()

# migrate v1 config ({"names": {mac: {"strip":.., "1":..}}}) -> v2 ("strips")
KNOWN = CFG.setdefault("strips", {})        # mac -> {label, ip, fw, last_seen, names{n:name}}
for _mac, _d in CFG.pop("names", {}).items():
    k = KNOWN.setdefault(_mac, {"names": {}})
    if _d.get("strip"):
        k["label"] = _d["strip"]
    k.setdefault("names", {}).update({n: v for n, v in _d.items() if n != "strip"})
for _k in KNOWN.values():
    _k.setdefault("autooff", {})
    _k.setdefault("names", {})
    _k.setdefault("types", {})
    _k.setdefault("rooms", {})
TIMERS = CFG.setdefault("timers", {})       # "MAC:n" -> {action: on/off, at: epoch}
SCHEDULES = CFG.setdefault("schedules", [])  # list of rule dicts
PENDING = {}                                 # (mac, n) -> (on, expires) for offline strips
EVENTS = collections.deque(maxlen=60)        # activity log for the UI



for _ts, _kind, _text in db("SELECT ts, kind, text FROM events ORDER BY id DESC LIMIT 60"):
    EVENTS.append({"ts": _ts, "text": _text, "kind": _kind})


def event(text, kind="info"):
    ts = time.time()
    EVENTS.appendleft({"ts": ts, "text": text, "kind": kind})
    log(text)
    try:
        db("INSERT INTO events(ts, kind, text) VALUES(?,?,?)", (ts, kind, text))
        db("DELETE FROM events WHERE id < (SELECT MAX(id) - 2000 FROM events)")
    except sqlite3.Error:
        pass


def outlet_type(mac, n):
    return KNOWN.get(mac, {}).get("types", {}).get(str(n), "")


def outlet_room(mac, n):
    return KNOWN.get(mac, {}).get("rooms", {}).get(str(n), "")


# ---- energy: the strip reports a cumulative Wh counter per outlet; we store daily deltas
LAST_E = {(m, n): e for m, n, e in db("SELECT mac, n, last_energy_wh FROM outlets WHERE last_energy_wh IS NOT NULL")}


def record_energy(mac, n, wh):
    last = LAST_E.get((mac, n))
    if last == wh:
        return
    LAST_E[(mac, n)] = wh
    if last is None:
        delta = 0                      # first reading ever: just a baseline
    elif wh >= last:
        delta = wh - last
    else:
        delta = wh                     # counter restarted (strip rebooted)
    if delta > 100000:                 # >100 kWh in one step = garbage
        delta = 0
    try:
        with _db_lock:
            db("UPDATE outlets SET last_energy_wh=? WHERE mac=? AND n=?", (wh, mac, n))
            if delta > 0:
                now = datetime.datetime.now()
                db("INSERT INTO energy_daily(day, mac, n, wh) VALUES(?,?,?,?) "
                   "ON CONFLICT(day, mac, n) DO UPDATE SET wh = wh + excluded.wh",
                   (now.date().isoformat(), mac, n, delta))
                db("INSERT INTO energy_hourly(hour, mac, n, wh) VALUES(?,?,?,?) "
                   "ON CONFLICT(hour, mac, n) DO UPDATE SET wh = wh + excluded.wh",
                   (now.strftime("%Y-%m-%d %H"), mac, n, delta))
    except sqlite3.Error as e:
        log("energy db error:", e)


def _month_add(d, k):
    m = d.year * 12 + (d.month - 1) + k
    return datetime.date(m // 12, m % 12 + 1, 1)


def _month_end(d):
    return _month_add(d, 1) - datetime.timedelta(days=1)


def energy_period(mode, day=None, frm=None, to=None):
    """Return (bucket_kind, start_date, end_date)."""
    today = datetime.date.today()
    if mode == "day":
        try:
            d = datetime.date.fromisoformat(day) if day else today
        except ValueError:
            d = today
        return "hour", d, d
    if mode == "month":
        return "day", today.replace(day=1), _month_end(today)
    if mode == "year":
        return "month", _month_add(today.replace(day=1), -11), today
    if mode == "custom":
        try:
            a, b = datetime.date.fromisoformat(frm), datetime.date.fromisoformat(to)
        except (TypeError, ValueError):
            a, b = today - datetime.timedelta(days=6), today
        if a > b:
            a, b = b, a
        if (b - a).days > 365:
            a = b - datetime.timedelta(days=365)
        return "day", a, b
    return "day", today - datetime.timedelta(days=6), today          # week


def _bucket_keys(kind, start, end):
    if kind == "hour":
        return ["%s %02d" % (start.isoformat(), h) for h in range(24)]
    if kind == "month":
        keys, d = [], start.replace(day=1)
        while d <= end:
            keys.append(d.strftime("%Y-%m"))
            d = _month_add(d, 1)
        return keys
    return [(start + datetime.timedelta(days=i)).isoformat() for i in range((end - start).days + 1)]


def _energy_rows(kind, start, end):
    """Yield (bucket_key, mac, n, wh)."""
    if kind == "hour":
        for h, mac, n, wh in db("SELECT hour, mac, n, wh FROM energy_hourly WHERE hour >= ? AND hour <= ?",
                                (start.isoformat() + " 00", end.isoformat() + " 23")):
            yield h, mac, n, wh
        return
    for d, mac, n, wh in db("SELECT day, mac, n, wh FROM energy_daily WHERE day >= ? AND day <= ?",
                            (start.isoformat(), end.isoformat())):
        yield (d[:7] if kind == "month" else d), mac, n, wh


def _sum_daily(a, b):
    """Total Wh between two dates, or None if fewer than 80% of the days have readings
    (comparing against a half-recorded period would be misleading)."""
    total, days = db("SELECT SUM(wh), COUNT(DISTINCT day) FROM energy_daily WHERE day >= ? AND day <= ?",
                     (a.isoformat(), b.isoformat()))[0]
    if not total or days < 0.8 * ((b - a).days + 1):
        return None
    return total


def _previous_total(mode, kind, start, end):
    """Usage in the comparable previous period (None when there is no data)."""
    today = datetime.date.today()
    if kind == "hour":
        prev = start - datetime.timedelta(days=1)
        last_h = datetime.datetime.now().hour if start == today else 23
        total, hours = db("SELECT SUM(wh), COUNT(DISTINCT hour) FROM energy_hourly WHERE hour >= ? AND hour <= ?",
                          (prev.isoformat() + " 00", "%s %02d" % (prev.isoformat(), last_h)))[0]
        if not total or hours < 0.6 * (last_h + 1):
            return None
        return total
    if mode == "month":
        pm = _month_add(start, -1)
        upto = min(today.day, _month_end(pm).day)
        return _sum_daily(pm, pm.replace(day=upto))
    if kind == "month":
        return _sum_daily(_month_add(start, -12), start - datetime.timedelta(days=1))
    length = (end - start).days + 1
    return _sum_daily(start - datetime.timedelta(days=length), start - datetime.timedelta(days=1))


def energy_report(mode="week", day=None, frm=None, to=None):
    kind, start, end = energy_period(mode, day, frm, to)
    keys = _bucket_keys(kind, start, end)
    pos = {k: i for i, k in enumerate(keys)}
    per = {}
    for key, mac, n, wh in _energy_rows(kind, start, end):
        if key in pos:
            per.setdefault((mac, n), [0.0] * len(keys))[pos[key]] += wh
    items = [{"mac": mac, "n": n, "name": outlet_label(mac, n), "strip": strip_label(mac),
              "type": outlet_type(mac, n), "room": outlet_room(mac, n),
              "buckets": [round(x, 1) for x in v], "total": round(sum(v), 1)}
             for (mac, n), v in per.items()]
    items.sort(key=lambda x: -x["total"])
    totals = [round(sum(it["buckets"][i] for it in items), 1) for i in range(len(keys))]
    prev = _previous_total(mode, kind, start, end)
    return {"mode": mode, "kind": kind, "start": start.isoformat(), "end": end.isoformat(),
            "keys": keys, "totals": totals, "total": round(sum(totals), 1),
            "prev_total": round(prev, 1) if prev else None,
            "items": items, "price": CFG.get("price_kwh", 0)}


# ---------------------------------------------------------------- tiny .xlsx writer (no dependencies)
def _col(i):
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def write_xlsx(sheets, rtl=False):
    """sheets: list of (name, rows, widths); first row is a bold header."""
    esc = lambda v: xml_escape(str(v)).replace('"', "&quot;")
    files = {}
    for si, (name, rows, widths) in enumerate(sheets, 1):
        out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
               '<sheetViews><sheetView workbookViewId="0"%s><pane ySplit="1" topLeftCell="A2" state="frozen"/></sheetView></sheetViews>'
               % (' rightToLeft="1"' if rtl else '')]
        out.append("<cols>%s</cols>" % "".join('<col min="%d" max="%d" width="%s" customWidth="1"/>' % (i + 1, i + 1, w)
                                                 for i, w in enumerate(widths)))
        out.append("<sheetData>")
        for ri, row in enumerate(rows, 1):
            cells = []
            for ci, v in enumerate(row):
                ref = "%s%d" % (_col(ci), ri)
                style = ' s="1"' if ri == 1 else (' s="2"' if isinstance(v, float) else "")
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    cells.append('<c r="%s"%s><v>%s</v></c>' % (ref, style, v))
                elif v not in (None, ""):
                    cells.append('<c r="%s" t="inlineStr"%s><is><t>%s</t></is></c>' % (ref, style, esc(v)))
            out.append('<row r="%d">%s</row>' % (ri, "".join(cells)))
        out.append("</sheetData></worksheet>")
        files["xl/worksheets/sheet%d.xml" % si] = "".join(out)
    names = [esc(n[:31]) for n, _, _ in sheets]
    files["[Content_Types].xml"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        + "".join('<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' % i
                  for i in range(1, len(sheets) + 1)) + "</Types>")
    files["_rels/.rels"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>")
    files["xl/workbook.xml"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
        + "".join('<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (n, i, i) for i, n in enumerate(names, 1))
        + "</sheets></workbook>")
    files["xl/_rels/workbook.xml.rels"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>' % (i, i)
                  for i in range(1, len(sheets) + 1))
        + '<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' % (len(sheets) + 1)
        + "</Relationships>")
    files["xl/styles.xml"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<numFmts count="1"><numFmt numFmtId="164" formatCode="0.000"/></numFmts>'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        '<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFF3E3CC"/><bgColor indexed="64"/></patternFill></fill></fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
        '<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        "</styleSheet>")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in ("[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/styles.xml"):
            z.writestr(name, files.pop(name))
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def energy_xlsx(rep_):
    en = CFG.get("lang") == "en"
    price = rep_["price"] or 0
    L = (lambda a, e: e if en else a)
    head = [L("الجهاز", "Appliance"), L("الغرفة", "Room"), L("المشترك", "Strip"), L("الفيشة", "Outlet"), "kWh"]
    if price:
        head.append(L("التكلفة (جنيه)", "Cost (EGP)"))
    rows = [head]
    for it in rep_["items"]:
        r = [it["name"], it["room"], it["strip"], it["n"], round(it["total"] / 1000.0, 3)]
        if price:
            r.append(round(it["total"] / 1000.0 * price, 2))
        rows.append(r)
    tot = [L("الإجمالي", "Total"), "", "", "", round(rep_["total"] / 1000.0, 3)]
    if price:
        tot.append(round(rep_["total"] / 1000.0 * price, 2))
    rows.append(tot)
    period_h = {"hour": L("الساعة", "Hour"), "day": L("اليوم", "Date"), "month": L("الشهر", "Month")}[rep_["kind"]]
    detail = [[period_h] + [it["name"] for it in rep_["items"]] + [L("الإجمالي", "Total")]]
    for i, k in enumerate(rep_["keys"]):
        label = (k[-2:] + ":00") if rep_["kind"] == "hour" else k
        detail.append([label] + [round(it["buckets"][i] / 1000.0, 3) for it in rep_["items"]]
                      + [round(rep_["totals"][i] / 1000.0, 3)])
    return write_xlsx([(L("ملخص", "Summary"), rows, [22, 16, 18, 9, 12, 14]),
                       (L("تفاصيل", "Detail"), detail, [14] + [16] * (len(rep_["items"]) + 1))], rtl=not en)


def today_wh():
    return {(m, n): wh for m, n, wh in db("SELECT mac, n, wh FROM energy_daily WHERE day = ?",
                                          (datetime.date.today().isoformat(),))}


def strip_label(mac):
    return KNOWN.get(mac, {}).get("label") or tr("مشترك ", "Strip ") + mac[-4:]


def outlet_label(mac, n):
    return KNOWN.get(mac, {}).get("names", {}).get(str(n)) or tr("فيشة %d", "Outlet %d") % n


def full_label(mac, n):
    return "%s / %s" % (strip_label(mac), outlet_label(mac, n))


# ---------------------------------------------------------------- strip sessions
class Strip:
    def __init__(self, sock, ip):
        self.sock = sock
        self.ip = ip
        self.mac = None
        self.model = ""
        self.fw = ""
        self.outlets = {n: {"n": n, "on": False, "power_w": 0.0, "energy_kwh": 0.0,
                            "temp_c": None, "fault": ""} for n in range(1, 5)}
        self.last_seen = time.time()
        self.connected_at = 0.0
        self.has_data = False
        self.wlock = threading.Lock()

    def send(self, cmd):
        with self.wlock:
            self.sock.sendall((cmd + "\r\n").encode("utf-8"))


STRIPS = {}          # mac -> Strip (online sessions only)
STRIPS_LOCK = threading.Lock()


def parse_getinfo(strip, line):
    recs = 0
    for m in GETINFO_RE.finditer(line[len("up:getinfo:"):]):
        ch = int(m.group("ch"))
        if ch > 4:
            continue
        fault = ""
        if m.group("ovl").lower() == "off" or m.group("event") == "01":
            fault = "overload"
        elif m.group("ovh").lower() == "off" or m.group("event") == "02":
            fault = "overheat"
        strip.outlets[ch].update({
            "on": m.group("relay").lower() == "on",
            "power_w": round(int(m.group("power")) / 1000.0, 1),
            "energy_kwh": round(int(m.group("energy"), 16) / 1000.0, 3),
            "temp_c": int(m.group("temp")),
            "fault": fault,
        })
        if strip.mac:
            record_energy(strip.mac, ch, int(m.group("energy"), 16))
        recs += 1
    if recs:
        strip.has_data = True


class DeviceHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        strip = Strip(sock, self.client_address[0])
        log("connection from", strip.ip)
        buf = b""
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                buf += data
                if len(buf) > 65536:
                    buf = b""
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    line = raw.replace(b"\x00", b"").decode("utf-8", "replace").strip()
                    if line:
                        self.on_line(strip, line)
                if buf and b"\x00" in buf:
                    line = buf.replace(b"\x00", b"").decode("utf-8", "replace").strip()
                    buf = b""
                    if line:
                        self.on_line(strip, line)
        except OSError:
            pass
        finally:
            with STRIPS_LOCK:
                gone = strip.mac and STRIPS.get(strip.mac) is strip
                if gone:
                    del STRIPS[strip.mac]
            if gone:
                with LOCK:
                    KNOWN.setdefault(strip.mac, {})["last_seen"] = time.time()
                    save_cfg()
                event(tr("%s فصل", "%s disconnected") % strip_label(strip.mac), "warn")
            try:
                sock.close()
            except OSError:
                pass

    def on_line(self, strip, line):
        strip.last_seen = time.time()
        m = BOOT_RE.match(line)
        if m:
            strip.model, strip.mac, strip.fw = m.group(1), m.group(2).upper(), m.group(4)
            strip.connected_at = time.time()
            with STRIPS_LOCK:
                old = STRIPS.get(strip.mac)
                STRIPS[strip.mac] = strip
            if old and old is not strip:
                try:
                    old.sock.close()
                except OSError:
                    pass
            with LOCK:
                new = strip.mac not in KNOWN
                k = KNOWN.setdefault(strip.mac, {})
                for _key in ("names", "types", "rooms", "autooff"):
                    k.setdefault(_key, {})
                k.update(ip=strip.ip, fw=strip.fw, last_seen=time.time())
                save_cfg()
            event((tr("مشترك جديد اتضاف: %s", "New strip added: %s") if new else tr("%s اتصل", "%s connected")) % strip_label(strip.mac), "ok")
            strip.send("up:getinfo:all")
            flush_pending(strip)
            return
        if line.startswith("up:getinfo:"):
            parse_getinfo(strip, line)
            return
        m = ONOFF_RE.match(line)
        if m and strip.mac:
            ch, on = int(m.group(1)), m.group(2).lower() == "on"
            for n in (range(1, 5) if ch == 0 else [ch]):
                strip.outlets[n]["on"] = on
                t = TIMERS.get("%s:%d" % (strip.mac, n))
                # outlet already reached the timer's target state (e.g. physical button) -> drop timer
                if t and (t["action"] == "on") == on and line.startswith("up:event"):
                    with LOCK:
                        TIMERS.pop("%s:%d" % (strip.mac, n), None)
                        save_cfg()


class ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _safe_send(s, cmd):
    try:
        s.send(cmd)
    except OSError:
        pass


def outlet_cmd(mac, n, on, reason=None):
    """Switch an outlet. If the strip is offline, queue it for when it reconnects."""
    s = STRIPS.get(mac)
    word = tr("تشغيل", "On") if on else tr("إطفاء", "Off")
    if s:
        try:
            s.send("up:onoff:%d:%s" % (n, "on" if on else "off"))
            s.outlets[n]["on"] = on
            threading.Timer(0.8, lambda: _safe_send(s, "up:getinfo:all")).start()
            if reason:
                event("%s %s (%s)" % (word, full_label(mac, n), reason), "ok")
            return True
        except OSError:
            pass
    PENDING[(mac, n)] = (on, time.time() + 1800)
    if reason:
        event(tr("%s مش متصل — %s %s هيتنفذ أول ما يرجع (%s)", "%s is offline — %s %s will run when it reconnects (%s)")
              % (strip_label(mac), word, outlet_label(mac, n), reason), "warn")
    return False


def flush_pending(strip):
    for (mac, n), (on, exp) in list(PENDING.items()):
        if mac != strip.mac:
            continue
        PENDING.pop((mac, n), None)
        if time.time() < exp:
            outlet_cmd(mac, n, on, tr("أمر متأجل", "queued command"))


def clear_timer(mac, n):
    with LOCK:
        if TIMERS.pop("%s:%d" % (mac, n), None):
            save_cfg()


def set_timer(mac, n, action, minutes):
    with LOCK:
        TIMERS["%s:%d" % (mac, n)] = {"action": action, "at": time.time() + minutes * 60}
        save_cfg()


# ---------------------------------------------------------------- schedules
def rule_next_fire(rule, now=None):
    """Next datetime the rule fires (within 8 days), or None."""
    if not rule.get("enabled", True):
        return None
    now = now or datetime.datetime.now()
    hh, mm = map(int, rule["time"].split(":"))
    for d in range(0, 8):
        day = (now + datetime.timedelta(days=d)).date()
        if rule.get("once_date"):
            if day.isoformat() != rule["once_date"]:
                continue
        elif day.weekday() not in rule.get("days", []):
            continue
        dt = datetime.datetime.combine(day, datetime.time(hh, mm))
        if dt > now:
            return dt
    return None


def fire_rule(rule):
    on = rule["action"] == "on"
    reason = tr("موعد: ", "Schedule: ") + (rule.get("name") or rule["time"])
    for mac, n in rule["targets"]:
        clear_timer(mac, n)
        outlet_cmd(mac, n, on, reason)
        if on and rule.get("duration_min"):
            set_timer(mac, n, "off", float(rule["duration_min"]))


def scheduler_loop():
    while True:
        time.sleep(5)
        now_ts = time.time()
        # one-shot timers
        for key, t in list(TIMERS.items()):
            if now_ts >= t["at"]:
                mac, n = key.rsplit(":", 1)
                clear_timer(mac, int(n))
                outlet_cmd(mac, int(n), t["action"] == "on",
                           tr("انتهى المؤقت", "timer ended") if t["action"] == "off" else tr("مؤقت", "timer"))
        try:
            autooff_check()
        except Exception as e:
            log("autooff error:", e)
        # schedules: fire if the scheduled minute passed less than 2 minutes ago
        now = datetime.datetime.now()
        changed = False
        for rule in list(SCHEDULES):
            if not rule.get("enabled", True):
                continue
            hh, mm = map(int, rule["time"].split(":"))
            due = datetime.datetime.combine(now.date(), datetime.time(hh, mm))
            if not (0 <= (now - due).total_seconds() < 120):
                continue
            if rule.get("once_date"):
                if rule["once_date"] != now.date().isoformat():
                    continue
            elif now.weekday() not in rule.get("days", []):
                continue
            stamp = due.strftime("%Y-%m-%d %H:%M")
            if rule.get("last_fired") == stamp:
                continue
            rule["last_fired"] = stamp
            if rule.get("once_date"):
                rule["enabled"] = False
            changed = True
            fire_rule(rule)
        if changed:
            with LOCK:
                save_cfg()


AO_STATE = {}   # (mac, n) -> {"armed": bool, "below": epoch or None}


def autooff_check():
    """Charger mode: once the outlet has drawn more than `w` watts (charging started),
    switch it off after it stays below `w` for `min` minutes (battery full)."""
    now = time.time()
    for mac, s in list(STRIPS.items()):
        if not s.has_data:
            continue
        for n in range(1, 5):
            cfg = KNOWN.get(mac, {}).get("autooff", {}).get(str(n))
            st = AO_STATE.setdefault((mac, n), {"armed": False, "below": None})
            o = s.outlets[n]
            if not cfg or not o["on"]:
                st.update(armed=False, below=None)
                continue
            if o["power_w"] > cfg["w"]:
                st.update(armed=True, below=None)
            elif st["armed"]:
                if st["below"] is None:
                    st["below"] = now
                elif now - st["below"] >= cfg["min"] * 60:
                    st.update(armed=False, below=None)
                    clear_timer(mac, n)
                    outlet_cmd(mac, n, False, tr("الشحن خلص", "charging finished"))


def poll_loop():
    while True:
        time.sleep(POLL_SECONDS)
        for s in list(STRIPS.values()):
            _safe_send(s, "up:getinfo:all")


def validate_rule(b):
    targets = []
    for t in b.get("targets", []):
        mac, n = str(t[0]).upper(), int(t[1])
        if not re.fullmatch(r"[0-9A-F]{12}", mac) or not 1 <= n <= 4:
            raise ValueError(tr("فيشة غلط", "Unknown outlet"))
        if [mac, n] not in targets:
            targets.append([mac, n])
    if not targets:
        raise ValueError(tr("اختار فيشة واحدة على الأقل", "Pick at least one outlet"))
    tm = str(b.get("time", ""))
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", tm):
        raise ValueError(tr("الساعة مش صحيحة", "Invalid time"))
    action = b.get("action")
    if action not in ("on", "off"):
        raise ValueError(tr("اختار تشغيل أو إطفاء", "Choose on or off"))
    once = b.get("once_date") or None
    days = sorted({int(d) for d in b.get("days", []) if 0 <= int(d) <= 6})
    if once:
        datetime.date.fromisoformat(once)
        days = []
    elif not days:
        raise ValueError(tr("اختار أيام التكرار أو تاريخ مرة واحدة", "Pick repeat days or a one-time date"))
    dur = float(b.get("duration_min") or 0) if action == "on" else 0
    if not 0 <= dur <= 24 * 60:
        raise ValueError(tr("المدة لازم تكون أقل من 24 ساعة", "Duration must be under 24 hours"))
    return {
        "id": str(b.get("id") or "r%d" % int(time.time() * 1000)),
        "name": str(b.get("name", "")).strip()[:40],
        "targets": targets, "time": tm, "action": action,
        "days": days, "once_date": once, "duration_min": dur,
        "enabled": bool(b.get("enabled", True)),
    }


# ---------------------------------------------------------------- guided setup (background job)
SETUP = {"running": False, "steps": [], "result": None}


def setup_step(text, kind="info"):
    SETUP["steps"].append({"t": time.strftime("%H:%M:%S"), "text": text, "kind": kind})
    log("setup:", text)


def setup_job(ssid, password, home_ip, auto_wifi):
    SETUP.update(running=True, steps=[], result=None)
    started = time.time()
    try:
        # 1) reach the strip's setup network
        host = setup_reachable()
        if not host and auto_wifi and IS_WIN:
            setup_step(tr("بدوّر على شبكة المشترك TONLY_TAP ...", "Looking for the strip's TONLY_TAP network..."))
            found = []
            for _ in range(4):
                found = setup_networks()
                if found:
                    break
                time.sleep(3)
            if not found:
                raise RuntimeError(tr("مش لاقي شبكة TONLY_TAP. اضغط زرار المشترك 10 ثواني لحد ما اللمبة تومض بسرعة، واستنى 20 ثانية وجرب تاني.",
                                       "No TONLY_TAP network found. Hold the strip's power button for 10 seconds until the light blinks fast, wait 20 seconds, and try again."))
            ap = found[0]
            setup_step(tr("لقيت %s — بتصل بيها (الباسورد %s)", "Found %s — connecting (password %s)") % (ap, setup_ap_password(ap)))
            for pw in (setup_ap_password(ap), None):
                wifi_connect_profile(ap, pw)
                for _ in range(10):
                    time.sleep(2)
                    host = setup_reachable()
                    if host:
                        break
                if host:
                    break
                if pw:
                    setup_step(tr("الباسورد مش ماشي، بجرب كشبكة مفتوحة ...", "Password rejected, trying as an open network..."), "warn")
        elif not host:
            setup_step(tr("مستني تتصل بشبكة TONLY_TAP يدوي ...", "Waiting for you to join the TONLY_TAP network..."))
            for _ in range(30):
                time.sleep(2)
                host = setup_reachable()
                if host:
                    break
        if not host:
            raise RuntimeError(tr("الجهاز مش قادر يوصل للمشترك على بورت 30300. اتأكد إنك متصل بشبكة TONLY_TAP واللمبة بتومض بسرعة.",
                                   "Can't reach the strip on port 30300. Make sure you're on the TONLY_TAP network and the light is blinking fast."))
        setup_step(tr("وصلت للمشترك على %s:%d", "Reached the strip at %s:%d") % (host, SETUP_PORT), "ok")

        # 2) send settings (one command per connection, as the firmware expects)
        r1 = setup_command(host, "up:ip:%s" % home_ip, "ip_ok")
        setup_step(tr("المشترك حفظ عنوان اللاب %s  (%s)", "Strip saved this computer's address %s  (%s)") % (home_ip, r1), "ok")
        r2 = setup_command(host, "up:connect:%s:%s" % (ssid, password), "connect_ok")
        setup_step(tr("المشترك حفظ شبكة البيت %s  (%s)", "Strip saved home Wi-Fi %s  (%s)") % (ssid, r2), "ok")
        try:
            setup_command(host, "up:reboot:0", None, timeout=3)
        except OSError:
            pass
        setup_step(tr("بعتّ أمر إعادة التشغيل — المشترك هيدخل على شبكة البيت", "Restart sent — the strip is joining your home Wi-Fi"), "ok")
        CFG.update(provisioned_ip=home_ip, home_ssid=ssid)
        save_cfg()

        # 3) back to home Wi-Fi
        if auto_wifi and IS_WIN:
            time.sleep(3)
            setup_step(tr("برجّع اللاب على شبكة %s ...", "Reconnecting this computer to %s...") % ssid)
            wifi_connect_existing(ssid)
        else:
            setup_step(tr("ارجع وصل اللاب بشبكة %s دلوقتي", "Reconnect this computer to %s now") % ssid, "warn")

        # 4) wait for the strip to dial in
        setup_step(tr("مستني المشترك يتصل باللاب (لحد دقيقتين) ...", "Waiting for the strip to connect (up to 2 minutes)..."))
        deadline = time.time() + 120
        next_wifi_check = time.time() + 25
        while time.time() < deadline:
            fresh = [s.mac for s in list(STRIPS.values()) if s.connected_at > started]
            if fresh:
                setup_step(tr("المشترك اتصل باللاب بنجاح! (%s) — روح على صفحة البيت", "Strip connected! (%s) — open the Home page") % ", ".join(fresh), "ok")
                SETUP["result"] = "ok"
                return
            if IS_WIN and auto_wifi and time.time() > next_wifi_check:
                next_wifi_check = time.time() + 25
                if wifi_current_ssid() != ssid:
                    wifi_connect_existing(ssid)
            time.sleep(2)
        now_ip = current_ip()
        hint = ""
        if now_ip and now_ip != home_ip:
            hint = tr(" — عنوان اللاب دلوقتي %s مش %s! اعمل الربط تاني بالعنوان الصح.",
                      " — this computer is now %s, not %s! Set up the strip again with the right address.") % (now_ip, home_ip)
        raise RuntimeError(tr("الإعدادات اتبعتت بس المشترك لسه ما اتصلش. اتأكد إن شبكة TONLY_TAP اختفت، وإن الفايروول فاتح بورت 10086، وافصل المشترك وشغله تاني.",
                               "Settings were sent but the strip hasn't connected yet. Check that TONLY_TAP disappeared, that the firewall allows port 10086, then unplug the strip and plug it back in.") + hint)
    except Exception as e:
        setup_step(str(e), "err")
        SETUP["result"] = "error"
    finally:
        SETUP["running"] = False


# ---------------------------------------------------------------- optional password
AUTH = CFG.setdefault("auth", {})          # {salt, hash, sessions: [token,...]}
LOGIN_FAILS = {}                           # ip -> [timestamps]


def auth_enabled():
    return bool(AUTH.get("hash"))


def _pw_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 200000).hex()


def set_password(password):
    with LOCK:
        if password:
            salt = secrets.token_hex(16)
            AUTH.update(salt=salt, hash=_pw_hash(password, salt), sessions=[])
        else:
            AUTH.clear()
        save_cfg()


def check_password(password):
    return auth_enabled() and hmac.compare_digest(_pw_hash(password, AUTH["salt"]), AUTH["hash"])


def new_session():
    tok = secrets.token_urlsafe(32)
    with LOCK:
        AUTH.setdefault("sessions", []).append(tok)
        AUTH["sessions"] = AUTH["sessions"][-20:]
        save_cfg()
    return tok


# ---------------------------------------------------------------- diagnostics
# MAC prefixes seen on MTTL-W01 units (TCL/Tonly). Used only to flag *possible* new strips.
STRIP_OUIS = ("88D039", "D8AA59")


def arp_table():
    out = {}
    for cmd in (["arp", "-a"], ["ip", "neigh"]):
        text, _, _ = run(cmd, timeout=10)
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+|dev\s+\S+\s+lladdr\s+)?"
                             r"([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})", text):
            mac = re.sub("[-:]", "", m.group(2)).upper()
            if mac not in ("FFFFFFFFFFFF", "000000000000") and not m.group(1).endswith(".255"):
                out[mac] = m.group(1)
        if out:
            break
    return out


def lan_sweep(ip):
    """Poke every address in the /24 so the OS fills its ARP table."""
    base = ip.rsplit(".", 1)[0]
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(0.2)
    for i in range(1, 255):
        try:
            u.sendto(b"\0", ("%s.%d" % (base, i), 9))
        except OSError:
            pass
    u.close()
    time.sleep(2.5)


def run_diagnostics():
    ip = current_ip()
    prov = CFG.get("provisioned_ip", "")
    if ip and not ip.startswith("127."):
        lan_sweep(ip)
    arp = arp_table()
    strips = []
    for mac in KNOWN:
        if mac in STRIPS:
            status, advice = "online", tr("متصل وشغال.", "Connected and working.")
        elif mac in arp:
            status = "on_lan"
            if prov and ip and prov != ip:
                advice = tr("المشترك على الشبكة بس متبرمج يكلم %s، واللاب دلوقتي %s. "
                            "اربطه تاني من صفحة \"إضافة مشترك\"، وثبّت عنوان اللاب من الراوتر.",
                            "The strip is on the network but set to reach %s, and this computer is now %s. "
                            "Set it up again from \"Add strip\", and reserve this computer's address in the router.") % (prov, ip)
            else:
                advice = tr("المشترك على الشبكة بس مش بيكلم البرنامج. افصل المشترك من الكهربا 5 ثواني ورجّعه. "
                            "لو فضل كده: اتأكد إن الفايروول فاتح بورت 10086 (شغّل Start-Strip.bat تاني ووافق على الصلاحية)، "
                            "أو اربطه تاني.",
                            "The strip is on the network but not talking to the app. Unplug it for 5 seconds and plug it back. "
                            "If that doesn't help: make sure the firewall allows port 10086 (run Start-Strip.bat again and approve), "
                            "or set it up again.")
        else:
            status = "missing"
            advice = tr("مش لاقيه على الشبكة. اتأكد إنه في الكهربا وإن الواي فاي شغال 2.4GHz. "
                        "لو غيّرت اسم الشبكة أو الباسورد لازم تربطه تاني.",
                        "Not found on the network. Check it's plugged in and the Wi-Fi is 2.4 GHz. "
                        "If you changed the Wi-Fi name or password, set it up again.")
        strips.append({"mac": mac, "label": strip_label(mac), "status": status,
                       "lan_ip": STRIPS[mac].ip if mac in STRIPS else arp.get(mac, ""), "advice": advice})
    unknown = [{"mac": m, "ip": a} for m, a in arp.items()
               if m.startswith(STRIP_OUIS) and m not in KNOWN]
    return {
        "laptop_ip": ip, "provisioned_ip": prov,
        "ip_ok": not prov or prov == ip,
        "devices_seen": len(arp),
        "strips": strips, "unknown": unknown,
    }


# ---------------------------------------------------------------- web API
def state_json():
    now = time.time()
    nowdt = datetime.datetime.now()
    # next scheduled event per outlet
    nxt = {}
    rules_out = []
    for r in SCHEDULES:
        nf = rule_next_fire(r, nowdt)
        rr = dict(r)
        rr["next"] = nf.timestamp() if nf else None
        rr["target_labels"] = [full_label(m, n) for m, n in r["targets"]]
        rules_out.append(rr)
        if nf:
            for m, n in r["targets"]:
                k = "%s:%d" % (m, n)
                if k not in nxt or nf.timestamp() < nxt[k]["at"]:
                    nxt[k] = {"at": nf.timestamp(), "action": r["action"]}
    devices = []
    twh = today_wh()
    for mac in sorted(KNOWN, key=lambda m: (m not in STRIPS, strip_label(m))):
        k = KNOWN[mac]
        s = STRIPS.get(mac)
        outs = []
        for n in range(1, 5):
            o = dict(s.outlets[n]) if s else {"n": n, "on": False, "power_w": 0.0,
                                              "energy_kwh": 0.0, "temp_c": None, "fault": ""}
            key = "%s:%d" % (mac, n)
            o["name"] = outlet_label(mac, n)
            o["named"] = bool(k.get("names", {}).get(str(n)))
            o["type"] = outlet_type(mac, n)
            o["room"] = outlet_room(mac, n)
            o["today_wh"] = round(twh.get((mac, n), 0.0), 1)
            ao = k.get("autooff", {}).get(str(n))
            if ao:
                st = AO_STATE.get((mac, n), {})
                left = None
                if st.get("below"):
                    left = max(0, int(st["below"] + ao["min"] * 60 - now))
                o["autooff"] = {"w": ao["w"], "min": ao["min"], "armed": bool(st.get("armed")), "left": left}
            else:
                o["autooff"] = None
            t = TIMERS.get(key)
            o["timer"] = {"action": t["action"], "left": max(0, int(t["at"] - now))} if t else None
            o["next"] = nxt.get(key)
            o["pending"] = (mac, n) in PENDING
            outs.append(o)
        devices.append({
            "mac": mac, "online": bool(s), "ip": s.ip if s else k.get("ip", ""),
            "fw": k.get("fw", ""), "label": strip_label(mac),
            "last_seen": k.get("last_seen"),
            "has_data": bool(s and s.has_data),
            "total_w": round(sum(o["power_w"] for o in outs if o["on"]), 1) if s else 0,
            "outlets": outs,
        })
    return {
        "now": now,
        "devices": devices,
        "schedules": sorted(rules_out, key=lambda r: r["time"]),
        "events": list(EVENTS)[:40],
        "current_ip": current_ip(),
        "provisioned_ip": CFG.get("provisioned_ip", ""),
        "home_ssid": CFG.get("home_ssid", ""),
        "is_windows": IS_WIN,
        "auth_enabled": auth_enabled(),
        "lang": CFG.get("lang", "ar"),
        "today_wh": round(sum(twh.values()), 1),
        "price_kwh": CFG.get("price_kwh", 0),
        "setup": SETUP,
    }


class Web(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", cookie=None, headers=None):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        for hk, hv in (headers or {}).items():
            self.send_header(hk, hv)
        if cookie is not None:
            self.send_header("Set-Cookie", "mttl_s=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                             % (cookie, 31536000 if cookie else 0))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 20000:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def _authed(self):
        if not auth_enabled():
            return True
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "mttl_s" and v and any(hmac.compare_digest(v, t) for t in AUTH.get("sessions", [])):
                return True
        return False

    def do_GET(self):
        p = urlparse(self.path).path
        if not self._authed():
            if p == "/":
                return self._send(200, login_html().encode("utf-8"), "text/html; charset=utf-8")
            return self._send(401, {"error": "login"})
        if p == "/":
            return self._send(200, page_html().encode("utf-8"), "text/html; charset=utf-8")
        if p == "/api/diag":
            return self._send(200, run_diagnostics())
        if p in ("/api/energy", "/api/energy.xlsx"):
            q = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
            mode = q.get("mode", "week")
            if mode not in ("day", "week", "month", "year", "custom"):
                mode = "week"
            r = energy_report(mode, q.get("day"), q.get("from"), q.get("to"))
            if p == "/api/energy":
                return self._send(200, r)
            return self._send(200, energy_xlsx(r),
                              "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                              headers={"Content-Disposition": 'attachment; filename="energy-%s-%s.xlsx"' % (r["start"], r["end"])})
        if p == "/api/state":
            return self._send(200, state_json())
        if p == "/api/wifi":
            return self._send(200, {
                "current_ssid": wifi_current_ssid(),
                "current_ip": current_ip(),
                "setup_networks": setup_networks(),
                "saved_home_ssid": CFG.get("home_ssid", ""),
            })
        self._send(404, {"error": "not found"})

    def do_POST(self):
        p = urlparse(self.path).path
        b = self._body()
        if p == "/api/login":
            ip = self.client_address[0]
            now = time.time()
            fails = [t for t in LOGIN_FAILS.get(ip, []) if now - t < 300]
            if len(fails) >= 8:
                return self._send(429, {"error": tr("محاولات كتير — استنى 5 دقايق", "Too many attempts — wait 5 minutes")})
            if check_password(str(b.get("password", ""))):
                LOGIN_FAILS.pop(ip, None)
                return self._send(200, {"ok": True}, cookie=new_session())
            time.sleep(1)
            LOGIN_FAILS[ip] = fails + [now]
            return self._send(403, {"error": tr("كلمة السر غلط", "Wrong password")})
        if not self._authed():
            return self._send(401, {"error": "login"})
        try:
            if p == "/api/password":
                pw = str(b.get("password", ""))
                if pw and len(pw) < 6:
                    return self._send(400, {"error": tr("كلمة السر لازم 6 حروف على الأقل", "Password must be at least 6 characters")})
                set_password(pw)
                return self._send(200, {"ok": True}, cookie=new_session() if pw else "")
            if p == "/api/logout":
                tok = ""
                for part in (self.headers.get("Cookie") or "").split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == "mttl_s":
                        tok = v
                with LOCK:
                    if tok in AUTH.get("sessions", []):
                        AUTH["sessions"].remove(tok)
                        save_cfg()
                return self._send(200, {"ok": True}, cookie="")
            if p == "/api/outlet":
                mac, n = b["mac"], int(b["n"])
                if mac not in STRIPS:
                    return self._send(409, {"error": tr("المشترك ده مش متصل دلوقتي", "That strip is offline right now")})
                clear_timer(mac, n)
                outlet_cmd(mac, n, bool(b["on"]))
                return self._send(200, {"ok": True})

            if p == "/api/all":
                macs = list(STRIPS) if b.get("mac") == "*" else [b["mac"]]
                macs = [m for m in macs if m in STRIPS]
                if not macs:
                    return self._send(409, {"error": tr("مفيش مشترك متصل", "No strip is connected")})
                for mac in macs:
                    for n in range(1, 5):
                        clear_timer(mac, n)
                        outlet_cmd(mac, n, bool(b["on"]))
                        time.sleep(0.12)
                if b.get("mac") == "*":
                    event(tr("تشغيل كل البيت", "Whole home on") if b["on"] else tr("إطفاء كل البيت", "Whole home off"), "ok")
                return self._send(200, {"ok": True})

            if p == "/api/outlet_meta":
                mac, n = b["mac"], int(b["n"])
                typ = str(b.get("type", ""))
                if typ and typ not in TYPES:
                    return self._send(400, {"error": tr("نوع جهاز غلط", "Unknown appliance type")})
                if mac not in KNOWN or not 1 <= n <= 4:
                    return self._send(400, {"error": tr("فيشة مش معروفة", "Unknown outlet")})
                with LOCK:
                    k = KNOWN[mac]
                    k.setdefault("names", {})[str(n)] = str(b.get("name", "")).strip()[:40]
                    k.setdefault("types", {})[str(n)] = typ
                    k.setdefault("rooms", {})[str(n)] = str(b.get("room", "")).strip()[:30]
                    save_cfg()
                return self._send(200, {"ok": True})

            if p == "/api/autooff":
                mac, n = b["mac"], int(b["n"])
                if mac not in KNOWN or not 1 <= n <= 4:
                    return self._send(400, {"error": tr("فيشة مش معروفة", "Unknown outlet")})
                with LOCK:
                    aos = KNOWN[mac].setdefault("autooff", {})
                    if b.get("enabled"):
                        w, mins = float(b.get("w", 5)), float(b.get("min", 5))
                        if not (0.5 <= w <= 200 and 1 <= mins <= 120):
                            return self._send(400, {"error": tr("الحد من 0.5 لـ 200 وات، والمدة من 1 لـ 120 دقيقة",
                                                                "Threshold must be 0.5–200 W and wait 1–120 minutes")})
                        aos[str(n)] = {"w": w, "min": mins}
                    else:
                        aos.pop(str(n), None)
                    AO_STATE.pop((mac, n), None)
                    save_cfg()
                return self._send(200, {"ok": True})

            if p == "/api/group":
                done = 0
                for t in b.get("targets", []):
                    mac, n = str(t[0]), int(t[1])
                    if mac in STRIPS and 1 <= n <= 4:
                        clear_timer(mac, n)
                        outlet_cmd(mac, n, bool(b["on"]))
                        done += 1
                        time.sleep(0.12)
                if not done:
                    return self._send(409, {"error": tr("مفيش فيش متصلة في المجموعة دي", "No connected outlets in this group")})
                if b.get("label"):
                    event((tr("تشغيل ", "On: ") if b["on"] else tr("إطفاء ", "Off: ")) + str(b["label"])[:40], "ok")
                return self._send(200, {"ok": True})

            if p == "/api/lang":
                if b.get("lang") not in ("ar", "en"):
                    return self._send(400, {"error": "lang"})
                with LOCK:
                    CFG["lang"] = b["lang"]
                    save_cfg()
                return self._send(200, {"ok": True})

            if p == "/api/price":
                price = float(b.get("price") or 0)
                if not 0 <= price <= 1000:
                    return self._send(400, {"error": tr("سعر غلط", "Invalid price")})
                with LOCK:
                    CFG["price_kwh"] = price
                    save_cfg()
                return self._send(200, {"ok": True})

            if p == "/api/name":
                mac, key = b["mac"], str(b["key"])
                name = str(b.get("name", "")).strip()[:40]
                with LOCK:
                    k = KNOWN.setdefault(mac, {"names": {}})
                    if key == "strip":
                        k["label"] = name
                    else:
                        k.setdefault("names", {})[key] = name
                    save_cfg()
                return self._send(200, {"ok": True})

            if p == "/api/timer":
                mac, n, mode = b["mac"], int(b["n"]), b.get("mode", "cancel")
                if mode == "cancel":
                    clear_timer(mac, n)
                    return self._send(200, {"ok": True})
                mins = float(b.get("minutes", 0))
                if not 0 < mins <= 7 * 24 * 60:
                    return self._send(400, {"error": tr("اكتب مدة صحيحة (دقيقة لحد 7 أيام)", "Enter a duration between 1 minute and 7 days")})
                if mac not in STRIPS:
                    return self._send(409, {"error": tr("المشترك ده مش متصل دلوقتي", "That strip is offline right now")})
                label = full_label(mac, n)
                if mode == "run_for":
                    outlet_cmd(mac, n, True)
                    set_timer(mac, n, "off", mins)
                    event(tr("%s شغالة لمدة %s", "%s on for %s") % (label, fmt_dur(mins)), "ok")
                elif mode == "off_after":
                    set_timer(mac, n, "off", mins)
                    event(tr("%s هتطفي بعد %s", "%s turns off in %s") % (label, fmt_dur(mins)))
                elif mode == "on_after":
                    set_timer(mac, n, "on", mins)
                    event(tr("%s هتشتغل بعد %s", "%s turns on in %s") % (label, fmt_dur(mins)))
                else:
                    return self._send(400, {"error": tr("نوع مؤقت غلط", "Unknown timer type")})
                return self._send(200, {"ok": True})

            if p == "/api/schedule":
                rule = validate_rule(b)
                with LOCK:
                    for i, r in enumerate(SCHEDULES):
                        if r["id"] == rule["id"]:
                            rule["last_fired"] = r.get("last_fired")
                            SCHEDULES[i] = rule
                            break
                    else:
                        SCHEDULES.append(rule)
                    save_cfg()
                event(tr("اتحفظ موعد: %s", "Schedule saved: %s") % (rule["name"] or rule["time"]))
                return self._send(200, {"ok": True, "id": rule["id"]})

            if p == "/api/schedule/toggle":
                with LOCK:
                    for r in SCHEDULES:
                        if r["id"] == b["id"]:
                            r["enabled"] = bool(b["enabled"])
                            if r["enabled"] and r.get("once_date") and not rule_next_fire(r):
                                r["enabled"] = False
                                save_cfg()
                                return self._send(400, {"error": tr("ميعاد المرة الواحدة ده عدّى — عدّل التاريخ", "That one-time date has passed — change it first")})
                    save_cfg()
                return self._send(200, {"ok": True})

            if p == "/api/schedule/delete":
                with LOCK:
                    SCHEDULES[:] = [r for r in SCHEDULES if r["id"] != b["id"]]
                    save_cfg()
                return self._send(200, {"ok": True})

            if p == "/api/schedule/run":
                for r in SCHEDULES:
                    if r["id"] == b["id"]:
                        fire_rule(r)
                return self._send(200, {"ok": True})

            if p == "/api/forget":
                mac = b["mac"]
                if mac in STRIPS:
                    return self._send(409, {"error": tr("المشترك متصل — افصله الأول", "The strip is connected — unplug it first")})
                with LOCK:
                    KNOWN.pop(mac, None)
                    for key in [k for k in TIMERS if k.startswith(mac + ":")]:
                        TIMERS.pop(key, None)
                    for r in SCHEDULES:
                        r["targets"] = [t for t in r["targets"] if t[0] != mac]
                    SCHEDULES[:] = [r for r in SCHEDULES if r["targets"]]
                    save_cfg()
                return self._send(200, {"ok": True})

            if p == "/api/setup":
                if SETUP["running"]:
                    return self._send(409, {"error": tr("الربط شغال بالفعل", "Setup is already running")})
                ssid = str(b.get("ssid", "")).strip()
                pw = str(b.get("password", ""))
                ip = str(b.get("home_ip", "")).strip()
                for v in (ssid, pw):
                    if any(c in v for c in ":\r\n"):
                        return self._send(400, {"error": tr("اسم الشبكة أو الباسورد فيه علامة : — المشترك مش بيقبلها", "The Wi-Fi name or password contains ':', which the strip can't accept")})
                if not ssid or len(pw) < 8:
                    return self._send(400, {"error": tr("اكتب اسم الشبكة وباسورد صحيح (8 حروف على الأقل)", "Enter the Wi-Fi name and a valid password (8+ characters)")})
                try:
                    ip = str(ipaddress.IPv4Address(ip))
                except ValueError:
                    return self._send(400, {"error": tr("عنوان IP مش صحيح", "Invalid IP address")})
                threading.Thread(target=setup_job, args=(ssid, pw, ip, bool(b.get("auto_wifi", True))),
                                 daemon=True).start()
                return self._send(200, {"ok": True})
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except (KeyError, TypeError, IndexError) as e:
            return self._send(400, {"error": tr("طلب ناقص: %s", "Incomplete request: %s") % e})
        except OSError as e:
            return self._send(500, {"error": tr("المشترك فصل: %s", "Strip disconnected: %s") % e})
        self._send(404, {"error": "not found"})


def fmt_dur(mins):
    mins = int(round(mins))
    h, m = divmod(mins, 60)
    if CFG.get("lang") == "en":
        hs = "%d h" % h
        if h and m:
            return "%s %d min" % (hs, m)
        return hs if h else "%d min" % max(m, 1)
    hs = "ساعة" if h == 1 else "ساعتين" if h == 2 else "%d ساعات" % h
    if h and m:
        return "%s و%d دقيقة" % (hs, m)
    return hs if h else "%d دقيقة" % max(m, 1)


# ---------------------------------------------------------------- page
PAGE = r"""<!DOCTYPE html>
<html lang="__LANG__" dir="__DIR__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0e141c">
<title>البيت الذكي</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Readex+Pro:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0e141c; --side:#111923; --panel:#16202b; --raise:#1b2633; --raise2:#223040;
  --line:#253242; --line2:#33465c; --text:#e8eef5; --muted:#8b9aae; --faint:#5f6f84;
  --copper:#e0a458; --copper-d:#3a2b18; --on:#3ddc97; --on-d:#113324; --off:#f06a6a; --off-d:#3a1a1e; --info:#7cb7ff;
  --r-lg:20px; --r-md:14px; --r-sm:10px;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--text);font-family:"Readex Pro",Tahoma,"Segoe UI",sans-serif;font-size:15px;line-height:1.5;
  font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
button,input,select{font:inherit;color:inherit}
button{cursor:pointer}
:focus-visible{outline:2px solid var(--copper);outline-offset:2px}
svg{flex:none}
.ltr{direction:ltr;unicode-bidi:isolate}

/* ---------- shell ---------- */
.app{display:grid;grid-template-columns:236px minmax(0,1fr);min-height:100vh}
.side{position:sticky;top:0;height:100vh;background:var(--side);border-inline-end:1px solid var(--line);display:flex;flex-direction:column;padding:22px 14px}
.brand{display:flex;align-items:center;gap:11px;padding:0 8px 26px}
.logo{width:38px;height:38px;border-radius:11px;background:var(--copper);color:#1d1408;display:grid;place-items:center}
.brand b{display:block;font-size:16px;font-weight:600}
.brand small{display:block;color:var(--muted);font-size:12px}
.nav{display:flex;flex-direction:column;gap:3px}
.nav button{display:flex;align-items:center;gap:12px;border:0;background:none;color:var(--muted);padding:10px 12px;border-radius:var(--r-sm);font-size:14.5px;text-align:start;position:relative}
.nav button:hover{color:var(--text);background:#ffffff06}
.nav button.on{color:var(--text);background:var(--raise)}
.nav button.on::before{content:"";position:absolute;inset-inline-start:-14px;top:9px;bottom:9px;width:3px;border-radius:3px;background:var(--copper)}
.side-foot{margin-top:auto;padding:0 8px;color:var(--faint);font-size:12px;line-height:1.7}
.main{min-width:0;padding:26px 34px 60px;max-width:1120px;width:100%}
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:22px;flex-wrap:wrap}
.top h1{margin:0;font-size:24px;font-weight:600;letter-spacing:-.01em}
.top p{margin:3px 0 0;color:var(--muted);font-size:13.5px}
.top-r{display:flex;align-items:center;gap:10px}
.conn{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--muted);background:var(--panel);border:1px solid var(--line);padding:7px 12px;border-radius:999px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--off)}
.dot.ok{background:var(--on);box-shadow:0 0 0 3px #3ddc9722}
.lang{border:1px solid var(--line);background:var(--panel);border-radius:999px;padding:7px 13px;font-size:13px;display:flex;gap:7px;align-items:center;color:var(--text)}
.lang:hover{border-color:var(--line2)}
.view{display:none}.view.on{display:block}

@media (max-width:860px){
  .app{grid-template-columns:1fr}
  .side{position:fixed;inset-inline:0;bottom:0;top:auto;height:auto;z-index:15;flex-direction:row;padding:6px 6px calc(6px + env(safe-area-inset-bottom));border-inline-end:0;border-top:1px solid var(--line)}
  .brand,.side-foot{display:none}
  .nav{flex-direction:row;width:100%;gap:0}
  .nav button{flex:1;flex-direction:column;gap:3px;font-size:11px;padding:7px 2px;justify-content:center}
  .nav button.on::before{inset-inline-start:30%;inset-inline-end:30%;top:-7px;bottom:auto;width:auto;height:3px}
  .main{padding:18px 14px 96px}
  .top h1{font-size:20px}
}

/* ---------- common ---------- */
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--r-lg);padding:20px}
.panel+.panel,.panel+.strip,.strip+.strip{margin-top:16px}
.panel h2{margin:0 0 3px;font-size:17px;font-weight:600}
.panel .lead{margin:0 0 16px;color:var(--muted);font-size:13.5px;line-height:1.7;max-width:70ch}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid var(--line2);background:var(--raise);color:var(--text);
  padding:10px 16px;border-radius:12px;font-weight:500;font-size:14px;white-space:nowrap;transition:background .15s,border-color .15s}
.btn:hover{border-color:#47607d;background:var(--raise2)}
.btn.primary{background:var(--copper);border-color:var(--copper);color:#1d1408;font-weight:600}
.btn.primary:hover{background:#eab36c}
.btn.primary:disabled{opacity:.5;cursor:not-allowed}
.btn.ghost{background:transparent}
.btn.danger{color:#ffa4a4}
.btn.sm{padding:7px 12px;font-size:13px;border-radius:10px}
.btn.block{width:100%}
.link{border:0;background:none;color:var(--muted);padding:0;font-size:12.5px;text-decoration:underline;text-underline-offset:3px}
.link:hover{color:var(--text)}
.ibtn{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);background:transparent;color:var(--muted);border-radius:9px;padding:6px 9px;font-size:12.5px}
.ibtn:hover:not(:disabled){color:var(--text);border-color:var(--line2)}
.ibtn:disabled{opacity:.4;cursor:not-allowed}
.seg{display:inline-flex;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:3px;gap:2px}
.seg button{border:0;background:none;color:var(--muted);padding:7px 14px;border-radius:9px;font-size:13.5px;font-weight:500}
.seg button.on{background:var(--raise2);color:var(--text)}
.seg.full{display:flex}.seg.full button{flex:1}
.hint{font-size:12.5px;color:var(--muted);line-height:1.65;margin:6px 0 0}
.warnbar{background:#2e2410;border:1px solid #5d4718;color:#f6d38e;border-radius:var(--r-md);padding:12px 16px;margin-bottom:16px;font-size:13.5px;line-height:1.7}
code{background:#0c1118;border:1px solid var(--line);border-radius:6px;padding:1px 6px;font-size:12.5px;direction:ltr;unicode-bidi:isolate}
label.f{display:block;font-size:13px;color:var(--muted);margin:14px 0 6px}
input[type=text],input[type=password],input[type=number],input[type=time],input[type=date]{width:100%;background:#0c1118;border:1px solid var(--line);
  color:var(--text);border-radius:11px;padding:10px 12px;font-size:15px;color-scheme:dark}
input:focus{outline:none;border-color:var(--copper)}
input[type=number]::-webkit-inner-spin-button,input[type=number]::-webkit-outer-spin-button{-webkit-appearance:none;margin:0}
input[type=number]{-moz-appearance:textfield;appearance:textfield}
.check{display:flex;gap:9px;align-items:center;margin-top:12px;font-size:13.5px;cursor:pointer}
.check input{accent-color:var(--copper);width:16px;height:16px}
.err{color:#ffaaaa;font-size:13px;margin-top:10px;min-height:1px}
.empty{text-align:center;padding:46px 22px}
.empty h2{margin:14px 0 6px;font-size:19px}
.empty p{color:var(--muted);margin:0 auto 20px;max-width:52ch;line-height:1.8}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--raise2);border:1px solid var(--line2);padding:11px 18px;border-radius:12px;font-size:13.5px;display:none;z-index:40;box-shadow:0 16px 40px #0008}
.toast.err-t{background:#3a1a1e;border-color:#6b2a30;color:#ffc6c6}
@media (max-width:860px){.toast{bottom:92px}}

/* ---------- home summary ---------- */
.summary{display:grid;grid-template-columns:1.25fr repeat(3,1fr) auto;background:var(--panel);border:1px solid var(--line);border-radius:var(--r-lg);margin-bottom:18px;overflow:hidden}
.sum{padding:18px 20px;border-inline-start:1px solid var(--line);min-width:0}
.sum:first-child{border-inline-start:0}
.sum .lbl{display:block;color:var(--muted);font-size:12.5px;margin-bottom:4px}
.sum b{font-size:22px;font-weight:500}
.sum b small{font-size:13px;color:var(--muted);font-weight:400;margin-inline-start:3px}
.sum .sub{display:block;font-size:12px;color:var(--muted);margin-top:2px}
.sum.main-w b{font-size:34px;font-weight:500;letter-spacing:-.02em}
.sum-acts{display:flex;flex-direction:column;gap:8px;justify-content:center}
.sum-acts .pair{display:flex;gap:6px}
.sum-acts .pair .btn{flex:1}
@media (max-width:1000px){.summary{grid-template-columns:repeat(2,1fr)}.sum{border-inline-start:0;border-top:1px solid var(--line)}.sum:nth-child(-n+2){border-top:0}.sum:nth-child(even){border-inline-start:1px solid var(--line)}.sum-acts{grid-column:1/-1;flex-direction:row;flex-wrap:wrap;border-inline-start:0!important}.sum-acts>*{flex:1}}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;flex-wrap:wrap}

/* ---------- strip = the physical power strip ---------- */
.strip{background:var(--panel);border:1px solid var(--line);border-radius:var(--r-lg);padding:18px 18px 16px}
.strip.is-off{opacity:.7}
.strip-h{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.strip-id{min-width:0}
.strip-name{background:none;border:0;border-bottom:1px dashed transparent;font-size:18px;font-weight:600;padding:1px 0;max-width:100%;color:var(--text)}
.strip-name:hover,.strip-name:focus{border-bottom-color:var(--faint);outline:none}
.meta{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:5px;font-size:12.5px;color:var(--muted)}
.pill{display:inline-flex;align-items:center;gap:6px;padding:2px 9px;border-radius:999px;background:var(--raise);font-size:12px;color:var(--muted)}
.pill i{width:6px;height:6px;border-radius:50%;background:var(--faint)}
.pill.ok{color:#9be8c4}.pill.ok i{background:var(--on)}
.strip-w{text-align:end}
.strip-w b{font-size:26px;font-weight:500}
.strip-w b small{font-size:13px;color:var(--muted);margin-inline-start:3px;font-weight:400}
.strip-w span{display:block;font-size:12px;color:var(--muted)}
.bar{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1px;background:var(--line);border:1px solid var(--line);border-radius:16px;overflow:hidden}
@media (max-width:860px){.bar{grid-template-columns:repeat(2,minmax(0,1fr))}}
.slot{background:var(--raise);padding:14px 12px 12px;display:flex;flex-direction:column;gap:9px;min-width:0}
.s-head{display:flex;align-items:center;gap:8px;border:0;background:none;padding:0;text-align:start;min-width:0;width:100%}
.s-head .n{flex:none;width:24px;height:24px;border-radius:50%;background:var(--raise2);border:1px solid var(--line2);display:grid;place-items:center;font-size:12px;font-weight:600;color:var(--muted)}
.slot.on .s-head .n{border-color:#3ddc9766;color:var(--on)}
.slot.off .s-head .n{border-color:#f06a6a55;color:#ff9b9b}
.s-head .nm{font-weight:600;font-size:14.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;flex:1}
.s-head .ed{color:var(--faint);opacity:0;transition:opacity .15s}
.s-head:hover .ed,.s-head:focus-visible .ed{opacity:1}
.s-sub{display:flex;align-items:center;gap:6px;min-height:20px;font-size:12.5px;color:var(--muted);white-space:nowrap;overflow:hidden}
.s-sub span{overflow:hidden;text-overflow:ellipsis}
.s-sub .link{color:var(--info);text-decoration:none;font-size:12.5px}
.socket{align-self:center;margin:4px 0 2px;width:92px;height:92px;border-radius:50%;border:0;position:relative;
  background:radial-gradient(circle at 50% 38%,#2b3644,#1a222d 72%);box-shadow:inset 0 2px 0 #ffffff12,inset 0 -8px 16px #0006,0 0 0 6px #121a24;transition:box-shadow .3s,background .3s}
.socket::before,.socket::after{content:"";position:absolute;top:50%;width:11px;height:11px;border-radius:50%;background:#0a0e13;transform:translateY(-50%);box-shadow:inset 0 2px 3px #000}
.socket::before{left:26px}.socket::after{right:26px}
.socket .ring{position:absolute;inset:-6px;border-radius:50%;border:2px solid var(--line2);transition:border-color .3s}
.slot.on .socket{background:radial-gradient(circle at 50% 38%,#1f4434,#11251c 72%);box-shadow:inset 0 2px 0 #ffffff12,0 0 0 6px #121a24,0 0 30px #3ddc9748}
.slot.on .socket .ring{border-color:var(--on)}
.slot.off .socket{background:radial-gradient(circle at 50% 38%,#33272a,#1d1719 72%)}
.slot.off .socket .ring{border-color:#f06a6aa8}
.socket:active:not(:disabled){transform:scale(.97)}
.socket:disabled{cursor:not-allowed}
.s-state{text-align:center;font-size:13px;font-weight:600;color:var(--faint)}
.slot.on .s-state{color:var(--on)}
.slot.off .s-state{color:#ff8f8f}
.reads{display:flex;justify-content:center;gap:12px;font-size:12px;color:var(--muted);flex-wrap:wrap}
.reads b{color:var(--text);font-weight:500;font-size:13.5px}
.chip-i{display:flex;align-items:center;justify-content:space-between;gap:6px;font-size:12px;border-radius:9px;padding:6px 9px;line-height:1.45}
.chip-i.t{background:var(--copper-d);color:#f2c48a}
.chip-i.s{background:#132235;color:var(--info)}
.chip-i .link{font-size:11.5px;color:inherit}
.fault{background:var(--off-d);color:#ffb3b3;border-radius:9px;padding:6px 9px;font-size:12px;text-align:center}
.s-acts{display:flex;gap:6px;justify-content:center;margin-top:auto;padding-top:2px}
.strip-f{display:flex;justify-content:flex-end;gap:8px;margin-top:12px}

/* ---------- rooms view ---------- */
.room{background:var(--panel);border:1px solid var(--line);border-radius:var(--r-lg);padding:6px 18px 8px}
.room+.room{margin-top:16px}
.room-h{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 0;flex-wrap:wrap}
.room-h h3{margin:0;font-size:17px;font-weight:600}
.room-h small{color:var(--muted);font-size:12.5px}
.room-h .acts{display:flex;gap:8px;align-items:center}
.room-h .w{font-size:15px;color:var(--muted);margin-inline-end:6px}
.row{display:grid;grid-template-columns:40px minmax(0,1fr) auto auto;gap:14px;align-items:center;padding:11px 0;border-top:1px solid var(--line)}
.row .ico{width:40px;height:40px;border-radius:12px;background:var(--raise);display:grid;place-items:center;color:var(--muted)}
.row.on .ico{color:var(--on);background:var(--on-d)}
.row .tx{min-width:0}
.row .tx b{display:block;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.row .tx small{color:var(--muted);font-size:12.5px}
.row .rd{text-align:end;font-size:12.5px;color:var(--muted);white-space:nowrap}
.row .rd b{display:block;color:var(--text);font-weight:500;font-size:14px}
.pilot{width:54px;height:30px;border-radius:999px;border:1px solid var(--line2);background:var(--raise);position:relative;transition:background .2s,border-color .2s}
.pilot::after{content:"";position:absolute;top:4px;inset-inline-start:4px;width:20px;height:20px;border-radius:50%;background:#ffffff22;transition:inset-inline-start .2s,background .2s,box-shadow .2s}
.row.on .pilot{background:var(--on-d);border-color:#3ddc9766}
.row.on .pilot::after{inset-inline-start:28px;background:var(--on);box-shadow:0 0 12px #3ddc97aa}
.row.off .pilot{border-color:#f06a6a66}
.row.off .pilot::after{background:var(--off);box-shadow:0 0 10px #f06a6a66}
.pilot:disabled{opacity:.45;cursor:not-allowed}
@media (max-width:560px){.row{grid-template-columns:40px minmax(0,1fr) auto}.row .rd{display:none}}

/* ---------- schedules ---------- */
.rules{padding:4px 20px}
.rule{display:grid;grid-template-columns:96px minmax(0,1fr) auto;gap:18px;align-items:center;padding:16px 0;border-top:1px solid var(--line)}
.rule:first-child{border-top:0}
.rule.dis{opacity:.5}
.r-time b{display:block;font-size:26px;font-weight:500;line-height:1.1;direction:ltr;text-align:start}
.r-time small{color:var(--muted);font-size:12.5px}
.r-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-weight:600}
.tag{font-size:12px;font-weight:500;padding:2px 9px;border-radius:999px}
.tag.on{background:var(--on-d);color:var(--on)}
.tag.off{background:var(--off-d);color:#ff9b9b}
.r-sub{color:var(--muted);font-size:13px;margin-top:3px}
.r-tg{display:flex;gap:5px;flex-wrap:wrap;margin-top:8px}
.r-tg span{font-size:12px;background:var(--raise);border-radius:7px;padding:2px 8px;color:#c6d1de}
.r-side{display:flex;flex-direction:column;align-items:flex-end;gap:10px}
.r-btns{display:flex;gap:4px}
.r-btns button{border:0;background:none;color:var(--faint);padding:5px;border-radius:8px;display:grid;place-items:center}
.r-btns button:hover{color:var(--text);background:var(--raise)}
@media (max-width:620px){.rule{grid-template-columns:1fr;gap:8px}.r-side{flex-direction:row;justify-content:space-between;align-items:center}}
.switch{position:relative;width:44px;height:25px;flex:none;display:inline-block}
.switch input{opacity:0;width:0;height:0;position:absolute}
.switch span{position:absolute;inset:0;background:var(--raise2);border-radius:99px;cursor:pointer;transition:.2s}
.switch span::after{content:"";position:absolute;top:3px;inset-inline-start:3px;width:19px;height:19px;border-radius:50%;background:#c5cfdb;transition:.2s}
.switch input:checked+span{background:var(--copper)}
.switch input:checked+span::after{inset-inline-start:22px;background:#1d1408}
.switch input:focus-visible+span{outline:2px solid var(--copper);outline-offset:2px}
.events{display:flex;flex-direction:column;max-height:380px;overflow:auto}
.ev{display:grid;grid-template-columns:52px 1fr;gap:10px;font-size:13.5px;padding:9px 0;border-top:1px solid var(--line);line-height:1.55}
.ev:first-child{border-top:0}
.ev time{color:var(--faint);font-size:12.5px;direction:ltr;text-align:start}
.ev.ok span{color:#a9ecd0}.ev.warn span{color:#f6d38e}.ev.err span{color:#ffb0b0}

/* ---------- energy ---------- */
.kpis{display:flex;flex-wrap:wrap;margin:-4px 0 20px}
.kpi{padding-inline-end:26px;margin-inline-end:26px;border-inline-end:1px solid var(--line);margin-top:4px}
.kpi:last-child{border:0}
.kpi .lbl{display:block;color:var(--muted);font-size:12.5px}
.kpi b{font-size:22px;font-weight:500}
.kpi b small{font-size:13px;color:var(--muted);font-weight:400;margin-inline-start:3px}
.chart{display:flex;align-items:flex-end;gap:5px;height:190px;border-bottom:1px solid var(--line);padding-top:10px}
.col{flex:1;height:100%;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;min-width:0}
.col i{display:block;width:100%;max-width:40px;background:linear-gradient(#e0a458,#c88a3e);border-radius:6px 6px 2px 2px;min-height:2px;opacity:.75}
.col.today i{opacity:1;box-shadow:0 0 18px #e0a45840}
.col b{font-size:11px;color:var(--muted);margin-bottom:4px;font-weight:400}
.col-l{display:flex;gap:5px;margin-top:7px}
.col-l span{flex:1;display:flex;justify-content:center;font-size:11px;color:var(--faint);min-width:0;overflow:visible;white-space:nowrap}
.price{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:18px}
.en-bar{justify-content:flex-start}
.en-pick{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.en-pick input{width:auto;padding:7px 10px;font-size:14px}
.en-pick .nav-d{border:1px solid var(--line);background:var(--panel);border-radius:9px;padding:6px 9px;color:var(--muted);display:grid;place-items:center}
.en-pick .nav-d:hover:not(:disabled){color:var(--text)}
.en-pick .nav-d:disabled{opacity:.35;cursor:not-allowed}
.cmp{display:inline-block;margin-top:4px;font-size:12.5px;padding:2px 8px;border-radius:999px}
.cmp.up{background:var(--off-d);color:#ffa4a4}.cmp.down{background:var(--on-d);color:var(--on)}.cmp.flat{background:var(--raise);color:var(--muted)}
.chart-h{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:4px;min-height:24px}
.chart-h b{font-weight:500;font-size:14px;color:var(--muted)}
.col.peak i{opacity:1}
.col:hover i{opacity:1;filter:brightness(1.12)}
.ap{cursor:pointer;border-radius:10px}
.ap:hover{background:#ffffff05}
.ap.sel{background:var(--copper-d)}
.ap.dim{opacity:.45}
.price input{width:110px}
.ap{display:grid;grid-template-columns:40px minmax(0,1fr) auto;gap:14px;align-items:center;padding:12px 0;border-top:1px solid var(--line)}
.ap:first-of-type{border-top:0}
.ap .ico{width:40px;height:40px;border-radius:12px;background:var(--raise);display:grid;place-items:center;color:var(--copper)}
.ap .tx b{font-weight:500}
.ap .tx small{color:var(--muted);font-size:12.5px;margin-inline-start:6px}
.meter{height:6px;border-radius:9px;background:var(--raise2);margin-top:7px;overflow:hidden}
.meter i{display:block;height:100%;background:var(--copper);border-radius:9px}
.ap .v{text-align:end;white-space:nowrap}
.ap .v b{display:block;font-weight:500}
.ap .v small{color:var(--muted);font-size:12.5px}

/* ---------- setup & settings ---------- */
.two{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,.9fr);gap:16px;align-items:start}
.two>.panel+.panel{margin-top:0}
@media (max-width:980px){.two{grid-template-columns:1fr}.two>.panel+.panel{margin-top:0}}
.steps{list-style:none;margin:0;padding:0;counter-reset:s}
.steps li{position:relative;padding-inline-start:40px;padding-bottom:16px;line-height:1.75;font-size:14px}
.steps li::before{counter-increment:s;content:counter(s);position:absolute;inset-inline-start:0;top:0;width:27px;height:27px;border-radius:50%;
  background:var(--raise);border:1px solid var(--line2);display:grid;place-items:center;font-size:12.5px;color:var(--copper)}
.log{margin-top:16px;display:flex;flex-direction:column;gap:6px;max-height:320px;overflow:auto}
.log div{font-size:13px;padding:8px 11px;border-radius:10px;background:var(--raise);line-height:1.6}
.log .ok{color:#a9ecd0}.log .err{color:#ffb0b0;background:var(--off-d)}.log .warn{color:#f6d38e}
.log time{color:var(--faint);margin-inline-end:8px;font-size:11.5px}
.dg{margin-top:16px;display:flex;flex-direction:column;gap:8px}
.dg-row{background:var(--raise);border-radius:12px;padding:12px 14px;border-inline-start:3px solid var(--line2)}
.dg-row.online{border-inline-start-color:var(--on)}.dg-row.on_lan{border-inline-start-color:var(--copper)}.dg-row.missing{border-inline-start-color:var(--off)}
.dg-row .t{display:flex;justify-content:space-between;gap:8px;font-weight:600;font-size:14px;flex-wrap:wrap}
.dg-row .t small{font-weight:400;color:var(--muted)}
.dg-row p{margin:6px 0 0;font-size:13px;color:var(--muted);line-height:1.7}
.dg-row.good p{color:#a9ecd0}

/* ---------- dialogs ---------- */
.modal{position:fixed;inset:0;background:#060a0fcc;display:none;align-items:flex-start;justify-content:center;padding:48px 14px;overflow:auto;z-index:30}
.modal.on{display:flex}
.dlg{background:var(--panel);border:1px solid var(--line2);border-radius:var(--r-lg);width:100%;max-width:540px;padding:22px;box-shadow:0 30px 80px #000a}
.dlg h3{margin:0 0 2px;font-size:18px;font-weight:600}
.dlg .sub{color:var(--muted);font-size:13px;margin:0 0 8px}
.dlg .row-btns{display:flex;gap:10px;margin-top:20px}
.dlg .row-btns .btn{flex:1}
@media (max-width:560px){.modal{align-items:flex-end;padding:0}.dlg{border-radius:20px 20px 0 0;max-height:92vh;overflow:auto;padding-bottom:calc(22px + env(safe-area-inset-bottom))}}
.types{display:grid;grid-template-columns:repeat(auto-fill,minmax(86px,1fr));gap:6px}
.types button{background:var(--raise);border:1px solid var(--line);border-radius:12px;padding:10px 4px 8px;font-size:12px;display:flex;flex-direction:column;align-items:center;gap:5px;color:var(--muted)}
.types button:hover{color:var(--text);border-color:var(--line2)}
.types button.on{border-color:var(--copper);background:var(--copper-d);color:#f2c48a}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.ao-box{margin-top:18px;padding:14px;border-radius:14px;background:var(--raise);border:1px solid var(--line)}
.ao-box b{font-weight:600}
.chip-i.c{background:#16301f;color:#8fe3bb}
.chip{border:1px solid var(--line);background:var(--raise);border-radius:999px;padding:5px 12px;font-size:12.5px;color:var(--text)}
.chip:hover{border-color:var(--line2)}
.chip.on{background:var(--copper-d);border-color:#6b4d22;color:#f2c48a}
.dur{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.dur div{position:relative}
.dur input{direction:ltr;text-align:left;padding:10px 92px 10px 12px}
.dur span{position:absolute;right:12px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none;max-width:78px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.preview{margin-top:14px;background:var(--copper-d);color:#f2c48a;border-radius:11px;padding:10px 13px;font-size:13.5px;line-height:1.6}
.tg-strip{border:1px solid var(--line);border-radius:12px;padding:10px 12px;margin-top:8px}
.tg-strip .h{display:flex;justify-content:space-between;align-items:center;font-weight:600;font-size:14px;margin-bottom:6px}
.tg-grid{display:grid;grid-template-columns:1fr 1fr;gap:2px}
.tg-grid label{display:flex;gap:8px;align-items:center;font-size:13.5px;padding:5px 2px;cursor:pointer;min-width:0}
.tg-grid label input{accent-color:var(--copper)}
.tg-grid label span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand">
      <div class="logo"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 4 14h7l-1 8 9-12h-7z"/></svg></div>
      <div><b data-t="app"></b><small data-t="appSub"></small></div>
    </div>
    <nav class="nav" id="nav"></nav>
    <div class="side-foot" data-t="sideFoot"></div>
  </aside>

  <main class="main">
    <header class="top">
      <div><h1 id="pg-title"></h1><p id="pg-sub"></p></div>
      <div class="top-r">
        <div class="conn"><span class="dot" id="dot"></span><span id="stxt"></span></div>
        <button class="lang" onclick="switchLang()" id="lang-btn"></button>
      </div>
    </header>

    <section id="v-home" class="view on">
      <div id="ipwarn" class="warnbar" style="display:none"></div>
      <div id="summary"></div>
      <div class="toolbar" id="toolbar"></div>
      <div id="devices"></div>
    </section>

    <section id="v-sched" class="view">
      <div class="toolbar"><span></span><button class="btn primary" onclick="openRule()" id="new-rule"></button></div>
      <div id="rules"></div>
      <div class="panel" style="margin-top:16px">
        <h2 data-t="logTitle"></h2>
        <p class="lead" data-t="logLead"></p>
        <div class="events" id="events"></div>
      </div>
    </section>

    <section id="v-energy" class="view">
      <div class="toolbar en-bar">
        <div class="seg" id="en-mode"><button data-v="day" data-t="pDay"></button><button data-v="week" class="on" data-t="pWeek"></button><button data-v="month" data-t="pMonth"></button><button data-v="year" data-t="pYear"></button><button data-v="custom" data-t="pCustom"></button></div>
        <div class="en-pick" id="en-pick"></div>
        <button class="btn sm" onclick="exportXlsx()" style="margin-inline-start:auto"><span id="xl-ico"></span><span data-t="export"></span></button>
      </div>
      <div class="panel">
        <div class="kpis" id="en-k"></div>
        <div class="chart-h"><b id="en-ttl"></b><button class="link" id="en-clear" onclick="EN.sel=null;drawEnergy()" style="display:none" data-t="showAll"></button></div>
        <div class="chart" id="en-bars"></div>
        <div class="col-l" id="en-lbl"></div>
        <div class="price"><span class="hint" style="margin:0" data-t="priceLbl"></span><input type="number" id="en-price" min="0" step="0.01" class="ltr"><span class="hint" style="margin:0" data-t="egp"></span><button class="btn sm" onclick="savePrice()" data-t="save"></button></div>
      </div>
      <div class="panel">
        <div class="toolbar" style="margin-bottom:6px"><h2 style="margin:0" data-t="breakdown"></h2>
          <div class="seg" id="en-group"><button data-v="app" class="on" data-t="byAppliance"></button><button data-v="room" data-t="byRoom"></button></div></div>
        <p class="hint" style="margin:0 0 6px" data-t="tapToFilter"></p>
        <div id="en-items"></div>
      </div>
    </section>

    <section id="v-setup" class="view">
      <div class="two">
        <div class="panel">
          <h2 data-t="setupTitle"></h2>
          <p class="lead" data-t="setupLead"></p>
          <label class="f" data-t="homeWifi"></label>
          <input type="text" id="ssid" autocomplete="off">
          <label class="f" data-t="homePw"></label>
          <input type="password" id="pwd" autocomplete="off">
          <label class="check"><input type="checkbox" id="showpw" onchange="pwd.type=this.checked?'text':'password'"><span data-t="showPw"></span></label>
          <label class="f" data-t="pcIp"></label>
          <input type="text" id="hip" class="ltr">
          <p class="hint" data-t="pcIpHint"></p>
          <label class="check" id="autorow"><input type="checkbox" id="auto" checked><span data-t="autoWifi"></span></label>
          <div style="margin-top:18px"><button class="btn primary block" id="go" onclick="startSetup()"></button></div>
          <div class="log" id="log"></div>
        </div>
        <div class="panel">
          <h2 data-t="beforeTitle"></h2>
          <p class="lead" data-t="beforeLead"></p>
          <ol class="steps"><li data-th="step1"></li><li data-th="step2"></li><li data-th="step3"></li><li data-th="step4"></li></ol>
          <p class="hint" data-th="manualHint"></p>
          <p class="hint" id="aplist"></p>
        </div>
      </div>
    </section>

    <section id="v-settings" class="view">
      <div class="two">
        <div class="panel">
          <h2 data-t="diagTitle"></h2>
          <p class="lead" data-t="diagLead"></p>
          <button class="btn primary block" id="diag-go" onclick="runDiag()"></button>
          <div id="diag"></div>
        </div>
        <div>
          <div class="panel">
            <h2 data-t="pwTitle"></h2>
            <p class="lead" id="pw-state"></p>
            <label class="f" data-t="pwNew"></label>
            <input type="password" id="pw1" autocomplete="new-password">
            <label class="f" data-t="pwAgain"></label>
            <input type="password" id="pw2" autocomplete="new-password">
            <div class="err" id="pw-err"></div>
            <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">
              <button class="btn primary" onclick="savePw()" data-t="pwSave"></button>
              <button class="btn ghost danger" id="pw-off" onclick="clearPw()" data-t="pwOff"></button>
              <button class="btn ghost" id="pw-logout" onclick="logout()" data-t="logout"></button>
            </div>
            <p class="hint" style="margin-top:14px" data-th="pwForgot"></p>
          </div>
          <div class="panel" style="margin-top:16px">
            <h2 data-t="langTitle"></h2>
            <p class="lead" data-t="langLead"></p>
            <div class="seg full" id="lang-seg"><button data-v="ar">العربية</button><button data-v="en">English</button></div>
          </div>
        </div>
      </div>
    </section>
  </main>
</div>

<!-- appliance dialog -->
<div class="modal" id="m-outlet" onclick="if(event.target===this)closeM('m-outlet')">
  <div class="dlg" role="dialog" aria-modal="true">
    <h3 data-t="olTitle"></h3>
    <p class="sub" id="ol-for"></p>
    <label class="f" data-t="olName"></label>
    <input type="text" id="ol-name" maxlength="40" data-tp="olNamePh">
    <label class="f" data-t="olType"></label>
    <div class="types" id="ol-types"></div>
    <label class="f" data-t="olRoom"></label>
    <input type="text" id="ol-room" maxlength="30" list="rooms-dl" data-tp="olRoomPh">
    <datalist id="rooms-dl"></datalist>
    <div class="chips" id="ol-rooms"></div>
    <div class="ao-box">
      <label class="check" style="margin-top:0"><input type="checkbox" id="ao-on" onchange="$('ao-f').style.display=this.checked?'grid':'none'"><span><b data-t="aoTitle"></b></span></label>
      <p class="hint" data-t="aoLead"></p>
      <div class="dur" id="ao-f" style="display:none;margin-top:10px">
        <div><input type="number" id="ao-w" min="0.5" max="200" step="0.5" value="5" class="ltr"><span data-t="aoW"></span></div>
        <div><input type="number" id="ao-m" min="1" max="120" value="5" class="ltr"><span data-t="aoMin"></span></div>
      </div>
    </div>
    <div class="err" id="ol-err"></div>
    <div class="row-btns"><button class="btn primary" onclick="saveOutlet()" data-t="save"></button><button class="btn ghost" onclick="closeM('m-outlet')" data-t="cancel"></button></div>
  </div>
</div>

<!-- timer dialog -->
<div class="modal" id="m-timer" onclick="if(event.target===this)closeM('m-timer')">
  <div class="dlg" role="dialog" aria-modal="true">
    <h3 data-t="timer"></h3>
    <p class="sub" id="t-for"></p>
    <div class="seg full" id="t-mode"><button data-v="run_for" class="on" data-t="runFor"></button><button data-v="off_after" data-t="offAfter"></button><button data-v="on_after" data-t="onAfter"></button></div>
    <label class="f" data-t="duration"></label>
    <div class="dur">
      <div><input type="number" id="t-h" min="0" max="168" value="0" class="ltr" inputmode="numeric"><span data-t="hours"></span></div>
      <div><input type="number" id="t-m" min="0" max="59" value="30" class="ltr" inputmode="numeric"><span data-t="minutes"></span></div>
    </div>
    <div class="chips" id="t-quick"></div>
    <div class="preview" id="t-prev"></div>
    <div class="err" id="t-err"></div>
    <div class="row-btns"><button class="btn primary" onclick="saveTimer()" data-t="start"></button><button class="btn ghost" onclick="closeM('m-timer')" data-t="cancel"></button></div>
  </div>
</div>

<!-- schedule dialog -->
<div class="modal" id="m-rule" onclick="if(event.target===this)closeM('m-rule')">
  <div class="dlg" role="dialog" aria-modal="true">
    <h3 id="r-title"></h3>
    <label class="f" data-t="rName"></label>
    <input type="text" id="r-name" maxlength="40" data-tp="rNamePh">
    <label class="f" data-t="rAction"></label>
    <div class="seg full" id="r-act"><button data-v="on" class="on" data-t="turnOn"></button><button data-v="off" data-t="turnOff"></button></div>
    <label class="f" data-t="rTime"></label>
    <input type="time" id="r-time" value="07:00" class="ltr">
    <label class="f" data-t="rWhen"></label>
    <div class="seg full" id="r-rep"><button data-v="days" class="on" data-t="repeatDays"></button><button data-v="once" data-t="once"></button></div>
    <div id="r-days-box">
      <div class="chips" id="r-days"></div>
      <div class="chips"><button class="link" onclick="setDays([0,1,2,3,4,5,6])" data-t="everyDay"></button><button class="link" onclick="setDays([6,0,1,2,3])" data-t="sunThu"></button><button class="link" onclick="setDays([4,5])" data-t="friSat"></button></div>
    </div>
    <div id="r-once-box" style="display:none;margin-top:10px"><input type="date" id="r-date" class="ltr"></div>
    <div id="r-dur-box">
      <label class="check"><input type="checkbox" id="r-dur-on" onchange="$('r-dur').style.display=this.checked?'grid':'none'"><span data-t="autoOff"></span></label>
      <div class="dur" id="r-dur" style="display:none;margin-top:8px">
        <div><input type="number" id="r-dh" min="0" max="24" value="1" class="ltr"><span data-t="hours"></span></div>
        <div><input type="number" id="r-dm" min="0" max="59" value="0" class="ltr"><span data-t="minutes"></span></div>
      </div>
    </div>
    <label class="f" data-t="rTargets"></label>
    <div id="r-targets"></div>
    <div class="err" id="r-err"></div>
    <div class="row-btns"><button class="btn primary" onclick="saveRule()" data-t="saveRule"></button><button class="btn ghost" onclick="closeM('m-rule')" data-t="cancel"></button></div>
  </div>
</div>
<div class="toast" id="toast" role="status"></div>

<script>
const $=id=>document.getElementById(id);
let S=null,LANG=document.documentElement.lang==='en'?'en':'ar',curTab='home',busy={},editing=false;

/* ---------------- icons ---------------- */
const sv=(d,s=18)=>`<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
const P={
  home:'<path d="M3 11l9-7.5L21 11"/><path d="M5.5 9.5V20h13V9.5"/><path d="M10 20v-5h4v5"/>',
  cal:'<rect x="3" y="4.5" width="18" height="16.5" rx="2.5"/><path d="M16 2.5v4M8 2.5v4M3 10h18"/>',
  chart:'<path d="M3 20.5h18"/><path d="M6 17V11M11 17V5M16 17v-8M21 17v-4"/>',
  plus:'<circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/>',
  sliders:'<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
  globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>',
  timer:'<circle cx="12" cy="13.5" r="7.5"/><path d="M12 10v3.5l2.2 2.2M9.5 2.5h5"/>',
  pencil:'<path d="M4 20h4L18.6 9.4a2.1 2.1 0 0 0-3-3L5 17v3z"/>',
  play:'<path d="M7 4.5v15l12-7.5z"/>',
  trash:'<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  power:'<path d="M12 3v9"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/>',
};
const TYPE_P={
  tv:'<rect x="2.5" y="6" width="19" height="13" rx="2"/><path d="M8 3l4 3 4-3"/>',
  heater:'<path d="M12 3c3.5 4 6 6.5 6 10.5a6 6 0 0 1-12 0c0-2.6 1.4-4.6 2.8-6.3.6 1.6 1.4 2.6 2.7 3-.8-2.4-.4-4.8.5-7.2z"/>',
  ac:'<path d="M12 2v20M3.3 7l17.4 10M20.7 7L3.3 17"/><path d="M9.5 3.5L12 6l2.5-2.5M9.5 20.5L12 18l2.5 2.5"/>',
  fridge:'<rect x="5.5" y="2.5" width="13" height="19" rx="2"/><path d="M5.5 10h13M9 5.5v2M9 13v3"/>',
  washer:'<rect x="3.5" y="2.5" width="17" height="19" rx="2"/><circle cx="12" cy="13" r="5"/><path d="M7 6h.01M10 6h.01"/>',
  kettle:'<path d="M5 9h11v5a5 5 0 0 1-5 5h-1a5 5 0 0 1-5-5z"/><path d="M16 10.5h1.5a2 2 0 0 1 0 4H16M8.5 2.5v3M12.5 2.5v3"/>',
  lamp:'<path d="M9 18h6M10 21h4"/><path d="M12 3a6 6 0 0 0-3.8 10.6c.6.5.8 1.3.8 2.4h6c0-1.1.2-1.9.8-2.4A6 6 0 0 0 12 3z"/>',
  fan:'<circle cx="12" cy="12" r="1.6"/><path d="M12 10.4C11 7 11.5 3.5 14 3.5c2.2 0 2 3.5-2 6.9M13.4 12.8c3.4.9 5.8 3.5 4.6 5.6-1.1 1.9-4-.2-5.4-4.9M10.6 12.8c-3.4.9-6.6.1-6.9-2.4-.2-2.2 3.3-2.5 6.9.9"/>',
  router:'<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01M8.5 9.5a5 5 0 0 1 7 0M5.8 6.8a9 9 0 0 1 12.4 0"/>',
  charger:'<rect x="2.5" y="7" width="16" height="10" rx="2"/><path d="M21.5 10.5v3M11.5 9l-2.5 3.5h3.5L10 16"/>',
  pc:'<rect x="2.5" y="3.5" width="19" height="13" rx="2"/><path d="M8 21h8M12 16.5V21"/>',
  pump:'<path d="M12 2.8l5.6 6a7.6 7.6 0 1 1-11.2 0z"/><path d="M9 14.5a3 3 0 0 0 3 3"/>',
  other:'<path d="M9 2.5V8M15 2.5V8M6 8h12v4a6 6 0 0 1-12 0zM12 18v3.5"/>',
};
const tIco=(t,s=18)=>sv(TYPE_P[t]||TYPE_P.other,s);

/* ---------------- text ---------------- */
const I18N={
ar:{
 app:'البيت الذكي',appSub:'مشتركات MTTL-W01',sideFoot:'شغال محلي على جهازك، من غير إنترنت ولا اشتراك.',
 navHome:'البيت',navSched:'المواعيد',navEnergy:'الاستهلاك',navAdd:'إضافة مشترك',navSettings:'الإعدادات',
 subHome:'كل المشتركات والفيش في مكان واحد',subSched:'شغّل أو اطفي أي فيشة في ميعاد ثابت',subEnergy:'استهلاك كل جهاز يوم بيوم',
 subAdd:'مرة واحدة لكل مشترك، وبعدها بيتصل لوحده',subSettings:'التشخيص وكلمة السر واللغة',
 connOf:'{0} من {1} متصل',connNone:'مفيش مشترك متصل',appOff:'البرنامج مقفول',
 drawNow:'بيسحب دلوقتي',outletsOn:'فيش شغالة',todayUse:'استهلاك النهارده',activeSched:'مواعيد مفعّلة',
 addStrip:'إضافة مشترك',allOn:'شغّل البيت',allOff:'اطفي البيت',byStrip:'حسب المشترك',byRoom:'حسب الغرفة',
 roomHint:'دوس على اسم أي فيشة وحدد الغرفة بتاعتها',online:'متصل',offAgo:'غير متصل {0}',whyMissing:'ليه مش ظاهر؟',remove:'إزالة',
 stripName:'اسم المشترك',stripDraw:'سحب المشترك',stripOn:'شغّل الكل',stripOff:'اطفي الكل',
 stOn:'شغالة',stOff:'مطفية',stNa:'غير متصل',kwhToday:'kWh النهارده',editOutlet:'تعديل الفيشة',setAppliance:'+ حدد الجهاز',
 timer:'مؤقت',schedule:'موعد',offIn:'هتطفي بعد {0}',onIn:'هتشتغل بعد {0}',cancelIt:'إلغاء',nextOn:'تشغيل {0}',nextOff:'إطفاء {0}',queued:'أمر مستني المشترك يرجع',
 overload:'حمل زائد — الفيشة فصلت للحماية',overheat:'سخونة زائدة — الفيشة فصلت للحماية',
 roomNone:'بدون غرفة',roomOn:'شغّل الغرفة',roomOff:'اطفي الغرفة',outletsCount:'{0} فيشة، {1} شغالة',outletOf:'{0}، فيشة {1}',
 emptyTitle:'مستني المشترك يتصل',emptyText:'لو ده أول مرة، ضيف المشترك واربطه بشبكة البيت. لو ربطته قبل كده، اتأكد إنه في الكهربا وإن الجهاز ده على نفس الشبكة، وافصل المشترك وشغله تاني.',scanNet:'افحص الشبكة',
 ipWarn:'عنوان الجهاز دلوقتي {0} لكن المشتركات متبرمجة على {1}. لو مشترك مش ظاهر: ثبّت العنوان من الراوتر، أو ضيف المشترك تاني.',
 confirmHouseOff:'تطفي كل الفيش في كل المشتركات؟',confirmGroupOff:'تطفي كل فيش "{0}"؟',confirmForget:'تشيل المشترك ده؟ المواعيد اللي عليه هتتشال كمان.',
 newRule:'+ موعد جديد',editRule:'تعديل موعد',logTitle:'السجل',logLead:'كل اللي حصل: مواعيد اتنفذت، مؤقتات، مشتركات اتصلت أو فصلت. المواعيد بتشتغل طول ما البرنامج مفتوح.',
 noRules:'مفيش مواعيد لسه',noRulesText:'مثلاً: شغّل السخان الساعة 6 الصبح لمدة ساعة من الأحد للخميس، أو اطفي التلفزيون كل يوم الساعة 1 بالليل.',
 unnamed:'موعد بدون اسم',ruleOn:'تشغيل',ruleOnFor:'تشغيل لمدة {0}',ruleOff:'إطفاء',nextAt:'الجاي: {0}',lastRun:'آخر تنفيذ {0}',edit:'تعديل',runNow:'نفّذ دلوقتي',del:'حذف',
 confirmDel:'تمسح الموعد ده؟',done:'اتنفذ',noEvents:'لسه مفيش حاجة.',
 rName:'اسم الموعد (اختياري)',rNamePh:'مثلاً: سخان الصبح',rAction:'يعمل إيه',turnOn:'تشغيل',turnOff:'إطفاء',rTime:'الساعة',rWhen:'إمتى',
 repeatDays:'أيام بتتكرر',once:'مرة واحدة',everyDay:'كل يوم',sunThu:'الأحد للخميس',friSat:'الجمعة والسبت',autoOff:'ويطفي لوحده بعد مدة',
 rTargets:'على أنهي فيش',pickRoom:'غرفة كاملة:',allOutlets:'كل الفيش',offlineTag:'(غير متصل)',saveRule:'حفظ الموعد',needDur:'اكتب مدة الإطفاء',connectFirst:'ضيف مشترك الأول.',
 runFor:'اشتغل لمدة',offAfter:'اطفي بعد',onAfter:'اشتغل بعد',duration:'المدة',hours:'ساعة',minutes:'دقيقة',start:'ابدأ',cancel:'رجوع',save:'حفظ',
 needMin:'اكتب مدة أكبر من صفر',pvRun:'هتشتغل دلوقتي، وتطفي {0}',pvOff:'هتفضل زي ما هي، وتطفي {0}',pvOn:'هتشتغل {0}',at:'{0} الساعة {1}',
 q15:'ربع ساعة',q30:'نص ساعة',q60:'ساعة',q120:'ساعتين',q240:'4 ساعات',q480:'8 ساعات',
 olTitle:'إيه المتوصل في الفيشة دي؟',olFor:'{0}، فيشة رقم {1}',olName:'اسم الفيشة',olNamePh:'مثلاً: تلفزيون الصالة',olType:'نوع الجهاز',olRoom:'الغرفة',olRoomPh:'مثلاً: الصالة',
 enLead:'محسوب من عداد كل فيشة. لو البرنامج كان مقفول، اللي اتصرف وقتها بيتحسب على أول يوم يفتح فيه.',d7:'7 أيام',d30:'30 يوم',
 pDay:'يوم',pWeek:'أسبوع',pMonth:'الشهر',pYear:'السنة',pCustom:'فترة',export:'Excel',from:'من',to:'إلى',showAll:'كل الأجهزة',breakdown:'التوزيع',tapToFilter:'دوس على أي جهاز علشان الرسم يوريك استهلاكه لوحده.',
 enTotal:'الاستهلاك',vsPrev:'{0} عن {1}',more:'أكتر',less:'أقل',same:'زي',prevDay:'امبارح',prevWeek:'الأسبوع اللي فات',prevMonth:'نفس الفترة الشهر اللي فات',prevYear:'السنة اللي قبلها',prevCustom:'الفترة اللي قبلها',prevOtherDay:'اليوم اللي قبله',
 avgHour:'متوسط الساعة',avgDay2:'متوسط اليوم',avgMonth:'متوسط الشهر',peakHour:'أعلى ساعة',peakDay:'أعلى يوم',peakMonth:'أعلى شهر',allDevices:'كل الأجهزة',noData:'لسه مفيش قراءات في الفترة دي.',hourNoteOld:'تفاصيل الساعات بتتسجل من النسخة دي وطالع.',
 total7:'إجمالي آخر 7 أيام',total30:'إجمالي آخر 30 يوم',avgDay:'متوسط اليوم',today:'النهارده',costEst:'التكلفة التقريبية',priceLbl:'سعر الكيلووات/ساعة',egp:'جنيه',
 byAppliance:'حسب الجهاز',noReadings:'لسه مفيش قراءات. الاستهلاك بيتسجل أول ما المشترك يتصل وأي جهاز يسحب كهربا.',savedPrice:'اتحفظ السعر',
 setupTitle:'ضيف مشترك واربطه بشبكة البيت',setupLead:'البرنامج بيبعت للمشترك اسم الواي فاي والباسورد وعنوان الجهاز ده. بعدها المشترك بيتصل لوحده كل ما يشتغل. اربطهم واحد واحد.',
 homeWifi:'شبكة البيت (2.4GHz)',homePw:'باسورد شبكة البيت',showPw:'إظهار الباسورد',pcIp:'عنوان الجهاز ده على شبكة البيت',
 pcIpHint:'ده العنوان اللي المشترك هيدوّر عليه دايماً. ثبّته من الراوتر (DHCP Reservation) عشان ما يتغيرش.',autoWifi:'البرنامج ينقل الواي فاي لوحده (يدخل على شبكة المشترك ويرجع)',
 goSetup:'ابدأ الربط',setupBusy:'جاري الربط…',retry:'جرّب تاني',beforeTitle:'قبل ما تدوس "ابدأ الربط"',beforeLead:'الجهاز ده لازم يكون على شبكة البيت وقت ما تدوس، عشان البرنامج يعرف عنوانه الصح.',
 step1:'اضغط زرار الباور الرئيسي في المشترك <b>10 ثواني</b> لحد ما اللمبة تومض بسرعة.',step2:'استنى 20 ثانية لحد ما شبكة <code>TONLY_TAP_…</code> تظهر.',
 step3:'دوس "ابدأ الربط". البرنامج هيدخل شبكة المشترك (باسوردها غالباً <code>LGU_</code> + آخر الاسم)، يبعت الإعدادات، ويرجع لشبكة البيت.',step4:'شبكة <code>TONLY_TAP</code> هتختفي، وخلال دقيقة المشترك يظهر في صفحة البيت.',
 manualHint:'لو النقل التلقائي ما نفعش: شيل علامة "ينقل الواي فاي لوحده"، دوس "ابدأ الربط"، واتصل بإيدك بشبكة <code>TONLY_TAP</code>. البرنامج هيستنى ويبعت أول ما يلاقيها.',apFound:'شبكات مشترك ظاهرة دلوقتي: ',
 diagTitle:'ليه المشترك مش ظاهر؟',diagLead:'البرنامج بيدوّر في شبكة البيت على كل مشترك يعرفه، ويقولك هو فين وإيه المشكلة. بياخد حوالي 5 ثواني.',diagGo:'افحص الشبكة',diagAgain:'افحص تاني',diagBusy:'بدوّر في الشبكة…',
 pcAddr:'عنوان الجهاز ده',noProv:'لسه ما ربطتش أي مشترك من البرنامج ده.',ipOk:'نفس العنوان اللي المشتركات متبرمجة عليه.',ipBad:'المشتركات متبرمجة على {0} والعنوان اتغير. ثبّت العنوان ده من الراوتر، أو ضيف المشتركات تاني.',
 dOnline:'متصل',dOnLan:'على الشبكة بس مش متصل',dMissing:'مش على الشبكة',setupAgain:'اربطه تاني',maybeNew:'جهاز ممكن يكون مشترك جديد',maybeNewText:'لقيت جهاز على الشبكة شكله مشترك ({0}) ومش متضاف هنا.',
 noStrips:'مفيش مشتركات',noStripsText:'ضيف مشترك من صفحة "إضافة مشترك".',scanned:'اتفحص {0} جهاز على الشبكة.',diagFail:'الفحص ما نفعش: {0}',
 pwTitle:'كلمة سر',pwOn:'كلمة السر مفعّلة. أي جهاز جديد يفتح البرنامج هيطلبها مرة واحدة.',pwNone:'مفيش كلمة سر دلوقتي. لازم تحطها قبل ما تفتح البرنامج من بره البيت.',
 pwNew:'كلمة السر الجديدة',pwAgain:'اكتبها تاني',pwSave:'حفظ كلمة السر',pwOff:'إلغاء كلمة السر',logout:'خروج من الجهاز ده',pwShort:'كلمة السر لازم 6 حروف على الأقل',pwMismatch:'الخانتين مش زي بعض',pwSaved:'اتحفظت كلمة السر',
 pwConfirmOff:'تلغي كلمة السر؟ أي حد على الشبكة هيقدر يتحكم.',pwForgot:'لو نسيت كلمة السر: اقفل البرنامج، وافتح <code>mttl.db</code> بأي برنامج SQLite، وامسح صف <code>auth</code> من جدول <code>settings</code>.',
 aoTitle:'اطفي لوحدها لما الشحن يخلص',aoLead:'للشواحن: لما الموبايل أو اللاب يوصل 100% السحب بيقع. لو فضل أقل من الحد ده المدة دي، الفيشة تفصل. بتشتغل بس بعد ما الشحن يبدأ فعلاً.',
 aoW:'وات (الحد)',aoMin:'دقيقة',aoWatch:'هتفصل لما الشحن يخلص',aoWait:'مستني الشحن يبدأ',aoCount:'الشحن خلص — هتفصل بعد {0}',
 langTitle:'اللغة',langLead:'لغة البرنامج والرسايل والسجل.',error:'حصل خطأ',
 types:{tv:'تلفزيون',heater:'سخان',ac:'تكييف',fridge:'تلاجة',washer:'غسالة',kettle:'غلاية',lamp:'إضاءة',fan:'مروحة',router:'راوتر',charger:'شاحن',pc:'كمبيوتر',pump:'موتور مياه',other:'تاني'},
 rooms:['الصالة','المطبخ','أوضة النوم','أوضة الأطفال','الحمام','المكتب','البلكونة'],
 days:['الاثنين','الثلاثاء','الأربعاء','الخميس','الجمعة','السبت','الأحد'],dShort:['اثنين','ثلاثاء','أربعاء','خميس','جمعة','سبت','أحد'],
 todayW:'النهارده',tomorrow:'بكرة',am:'ص',pm:'م',morning:'صباحاً',evening:'مساءً',
 agoMin:'من دقيقة',agoM:'من {0} دقيقة',agoH:'من {0} ساعة',agoD:'من {0} يوم',sep:'، ',
},
en:{
 app:'Smart Home',appSub:'MTTL-W01 strips',sideFoot:'Runs locally on this computer. No internet or subscription.',
 navHome:'Home',navSched:'Schedules',navEnergy:'Energy',navAdd:'Add strip',navSettings:'Settings',
 subHome:'Every strip and outlet in one place',subSched:'Turn any outlet on or off at a set time',subEnergy:'What each appliance uses, day by day',
 subAdd:'Once per strip — after that it connects by itself',subSettings:'Diagnostics, password and language',
 connOf:'{0} of {1} connected',connNone:'No strip connected',appOff:'App is closed',
 drawNow:'Drawing now',outletsOn:'Outlets on',todayUse:'Used today',activeSched:'Active schedules',
 addStrip:'Add strip',allOn:'All on',allOff:'All off',byStrip:'By strip',byRoom:'By room',
 roomHint:'Tap an outlet name to set its room',online:'Online',offAgo:'Offline {0}',whyMissing:'Why is it missing?',remove:'Remove',
 stripName:'Strip name',stripDraw:'Strip draw',stripOn:'Turn all on',stripOff:'Turn all off',
 stOn:'On',stOff:'Off',stNa:'Offline',kwhToday:'kWh today',editOutlet:'Edit outlet',setAppliance:'+ Set appliance',
 timer:'Timer',schedule:'Schedule',offIn:'Off in {0}',onIn:'On in {0}',cancelIt:'Cancel',nextOn:'On {0}',nextOff:'Off {0}',queued:'Command waiting for the strip',
 overload:'Overload — outlet cut off for safety',overheat:'Overheat — outlet cut off for safety',
 roomNone:'No room',roomOn:'Room on',roomOff:'Room off',outletsCount:'{0} outlets, {1} on',outletOf:'{0}, outlet {1}',
 emptyTitle:'Waiting for a strip to connect',emptyText:'First time? Add your strip and connect it to your home Wi-Fi. Already set up? Check it\'s plugged in and this computer is on the same network, then unplug the strip and plug it back in.',scanNet:'Scan network',
 ipWarn:'This computer is now {0}, but your strips are set to reach {1}. If a strip is missing, reserve this address in your router or add the strip again.',
 confirmHouseOff:'Turn off every outlet on every strip?',confirmGroupOff:'Turn off every outlet in "{0}"?',confirmForget:'Remove this strip? Its schedules will be removed too.',
 newRule:'+ New schedule',editRule:'Edit schedule',logTitle:'Activity',logLead:'Everything that happened: schedules that ran, timers, strips connecting or dropping. Schedules run while the app is open.',
 noRules:'No schedules yet',noRulesText:'For example: water heater on at 6 AM for an hour, Sunday to Thursday — or the TV off every night at 1 AM.',
 unnamed:'Untitled schedule',ruleOn:'On',ruleOnFor:'On for {0}',ruleOff:'Off',nextAt:'Next: {0}',lastRun:'Last ran {0}',edit:'Edit',runNow:'Run now',del:'Delete',
 confirmDel:'Delete this schedule?',done:'Done',noEvents:'Nothing yet.',
 rName:'Name (optional)',rNamePh:'e.g. Morning heater',rAction:'Action',turnOn:'Turn on',turnOff:'Turn off',rTime:'Time',rWhen:'When',
 repeatDays:'Repeat on days',once:'Once',everyDay:'Every day',sunThu:'Sun to Thu',friSat:'Fri and Sat',autoOff:'Turn off automatically after',
 rTargets:'Outlets',pickRoom:'Whole room:',allOutlets:'All outlets',offlineTag:'(offline)',saveRule:'Save schedule',needDur:'Enter how long before it turns off',connectFirst:'Add a strip first.',
 runFor:'On for',offAfter:'Off after',onAfter:'On after',duration:'Duration',hours:'hours',minutes:'minutes',start:'Start',cancel:'Cancel',save:'Save',
 needMin:'Enter a duration above zero',pvRun:'Turns on now and off {0}',pvOff:'Stays as is, turns off {0}',pvOn:'Turns on {0}',at:'{0} at {1}',
 q15:'15 min',q30:'30 min',q60:'1 hour',q120:'2 hours',q240:'4 hours',q480:'8 hours',
 olTitle:'What\'s plugged in here?',olFor:'{0}, outlet {1}',olName:'Outlet name',olNamePh:'e.g. Living room TV',olType:'Appliance type',olRoom:'Room',olRoomPh:'e.g. Living room',
 enLead:'Calculated from each outlet\'s meter. If the app was closed, that usage is counted on the day it reopens.',d7:'7 days',d30:'30 days',
 pDay:'Day',pWeek:'Week',pMonth:'Month',pYear:'Year',pCustom:'Range',export:'Excel',from:'From',to:'To',showAll:'All appliances',breakdown:'Breakdown',tapToFilter:'Tap an appliance to chart it on its own.',
 enTotal:'Used',vsPrev:'{0} than {1}',more:'more',less:'less',same:'same as',prevDay:'yesterday',prevWeek:'the previous week',prevMonth:'the same days last month',prevYear:'the previous year',prevCustom:'the previous period',prevOtherDay:'the day before',
 avgHour:'Hourly average',avgDay2:'Daily average',avgMonth:'Monthly average',peakHour:'Peak hour',peakDay:'Peak day',peakMonth:'Peak month',allDevices:'All appliances',noData:'No readings in this period yet.',hourNoteOld:'Hourly detail is recorded from this version on.',
 total7:'Last 7 days',total30:'Last 30 days',avgDay:'Daily average',today:'Today',costEst:'Estimated cost',priceLbl:'Price per kWh',egp:'EGP',
 byAppliance:'By appliance',noReadings:'No readings yet. Usage is recorded once a strip connects and something draws power.',savedPrice:'Price saved',
 setupTitle:'Add a strip and connect it to your Wi-Fi',setupLead:'The app sends the strip your Wi-Fi name, password and this computer\'s address. After that the strip connects on its own every time it powers up. Add strips one at a time.',
 homeWifi:'Home Wi-Fi (2.4 GHz)',homePw:'Wi-Fi password',showPw:'Show password',pcIp:'This computer\'s address on your Wi-Fi',
 pcIpHint:'The strip will always look for this address. Reserve it in your router (DHCP reservation) so it never changes.',autoWifi:'Switch Wi-Fi automatically (join the strip\'s network and come back)',
 goSetup:'Start setup',setupBusy:'Setting up…',retry:'Try again',beforeTitle:'Before you press "Start setup"',beforeLead:'This computer must be on your home Wi-Fi when you press it, so the app knows its correct address.',
 step1:'Hold the strip\'s main power button for <b>10 seconds</b> until the light blinks fast.',step2:'Wait about 20 seconds for the <code>TONLY_TAP_…</code> network to appear.',
 step3:'Press "Start setup". The app joins the strip\'s network (password is usually <code>LGU_</code> + the end of its name), sends the settings, and returns to your Wi-Fi.',step4:'<code>TONLY_TAP</code> disappears and within a minute the strip shows up on Home.',
 manualHint:'If automatic switching fails: untick "Switch Wi-Fi automatically", press "Start setup", then join <code>TONLY_TAP</code> yourself. The app waits and sends the settings as soon as it finds it.',apFound:'Strip networks visible now: ',
 diagTitle:'Why is a strip missing?',diagLead:'Searches your home network for every strip the app knows and tells you where it is and what\'s wrong. Takes about 5 seconds.',diagGo:'Scan network',diagAgain:'Scan again',diagBusy:'Scanning…',
 pcAddr:'This computer\'s address',noProv:'No strip has been set up from this app yet.',ipOk:'Same address your strips are set to reach.',ipBad:'Your strips are set to reach {0} but the address changed. Reserve that address in your router, or add the strips again.',
 dOnline:'Connected',dOnLan:'On the network but not connected',dMissing:'Not on the network',setupAgain:'Set it up again',maybeNew:'Possibly a new strip',maybeNewText:'Found a device that looks like a strip ({0}) that isn\'t added here.',
 noStrips:'No strips',noStripsText:'Add one from "Add strip".',scanned:'Checked {0} devices on the network.',diagFail:'Scan failed: {0}',
 pwTitle:'Password',pwOn:'Password is on. Any new device opening the app will ask for it once.',pwNone:'No password set. Add one before opening the app from outside your home.',
 pwNew:'New password',pwAgain:'Type it again',pwSave:'Save password',pwOff:'Remove password',logout:'Sign out on this device',pwShort:'Password must be at least 6 characters',pwMismatch:'The two fields don\'t match',pwSaved:'Password saved',
 pwConfirmOff:'Remove the password? Anyone on your network will be able to control the strips.',pwForgot:'Forgot it? Close the app, open <code>mttl.db</code> in any SQLite tool, and delete the <code>auth</code> row from the <code>settings</code> table.',
 aoTitle:'Turn off when charging is done',aoLead:'For chargers: when a phone or laptop reaches 100% the draw drops. If it stays below this limit for this long, the outlet switches off. It only arms after charging has actually started.',
 aoW:'W (limit)',aoMin:'minutes',aoWatch:'Turns off when charging is done',aoWait:'Waiting for charging to start',aoCount:'Charging done — off in {0}',
 langTitle:'Language',langLead:'Language for the app, messages and activity log.',error:'Something went wrong',
 types:{tv:'TV',heater:'Water heater',ac:'Air con',fridge:'Fridge',washer:'Washer',kettle:'Kettle',lamp:'Lights',fan:'Fan',router:'Router',charger:'Charger',pc:'Computer',pump:'Water pump',other:'Other'},
 rooms:['Living room','Kitchen','Bedroom','Kids room','Bathroom','Office','Balcony'],
 days:['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'],dShort:['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],
 todayW:'Today',tomorrow:'Tomorrow',am:'AM',pm:'PM',morning:'AM',evening:'PM',
 agoMin:'a minute ago',agoM:'{0} min ago',agoH:'{0} h ago',agoD:'{0} days ago',sep:', ',
}};
function t(k,...a){let s=(I18N[LANG][k]??I18N.ar[k]??k);if(typeof s==='string')a.forEach((v,i)=>{s=s.split('{'+i+'}').join(v)});return s}
const DAY_ORDER_AR=[5,6,0,1,2,3,4], DAY_ORDER_EN=[6,0,1,2,3,4,5];
const dayOrder=()=>LANG==='ar'?DAY_ORDER_AR:DAY_ORDER_EN;

/* ---------------- helpers ---------------- */
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const two=n=>String(n).padStart(2,'0');
const kwh=wh=>(wh/1000).toFixed(wh>=10000?1:2);
const money=wh=>S&&S.price_kwh?(wh/1000*S.price_kwh).toFixed(2)+' '+t('egp'):'';
function fmtLeft(s){const h=Math.floor(s/3600),m=Math.floor(s%3600/60),x=s%60;return h?h+':'+two(m)+':'+two(x):m+':'+two(x)}
function clock(h,m){return (h%12||12)+':'+two(m)+' '+(h<12?t('am'):t('pm'))}
const clockOf=d=>clock(d.getHours(),d.getMinutes());
function dayWord(d){const a=new Date();a.setHours(0,0,0,0);const b=new Date(d);b.setHours(0,0,0,0);const diff=Math.round((b-a)/864e5);
  return diff===0?t('todayW'):diff===1?t('tomorrow'):t('days')[(d.getDay()+6)%7]}
const whenText=ts=>{const d=new Date(ts*1000);return dayWord(d)+' '+clockOf(d)};
function durText(min){min=Math.round(min);const h=Math.floor(min/60),m=min%60;
  if(LANG==='en')return h&&m?h+' h '+m+' min':h?h+' h':m+' min';
  const hs=h===1?'ساعة':h===2?'ساعتين':h+' ساعات';return h&&m?hs+' و'+m+' دقيقة':h?hs:m+' دقيقة'}
function daysText(r){
  if(r.once_date){const d=new Date(r.once_date+'T00:00');return t('once')+t('sep')+d.toLocaleDateString(LANG==='ar'?'ar-EG-u-nu-latn':'en-GB',{weekday:'long',day:'numeric',month:'long'})}
  const s=[...r.days].sort().join(',');
  if(r.days.length===7)return t('everyDay');if(s==='0,1,2,3,6')return t('sunThu');if(s==='4,5')return t('friSat');
  return dayOrder().filter(d=>r.days.includes(d)).map(d=>t('dShort')[d]).join(t('sep'));
}
function ago(ts){if(!ts)return '';const s=Date.now()/1000-ts;if(s<90)return t('agoMin');if(s<3600)return t('agoM',Math.round(s/60));if(s<86400)return t('agoH',Math.round(s/3600));return t('agoD',Math.round(s/86400))}
const typeLabel=k=>t('types')[k]||'';
function toast(m,isErr){const e=$('toast');e.textContent=m;e.className='toast'+(isErr?' err-t':'');e.style.display='block';clearTimeout(e._h);e._h=setTimeout(()=>e.style.display='none',3800)}
async function api(p,b){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
  if(r.status===401){location.reload();return {}}let j={};try{j=await r.json()}catch(e){}if(!r.ok)throw new Error(j.error||t('error'));return j}
async function getJSON(p){const r=await fetch(p);if(r.status===401){location.reload();throw new Error('login')}return r.json()}

/* ---------------- navigation & language ---------------- */
const TABS=[['home','navHome','subHome',P.home],['sched','navSched','subSched',P.cal],['energy','navEnergy','subEnergy',P.chart],['setup','navAdd','subAdd',P.plus],['settings','navSettings','subSettings',P.sliders]];
function buildNav(){$('nav').innerHTML=TABS.map(([id,l,,ic])=>`<button id="tab-${id}" class="${curTab===id?'on':''}" onclick="tab('${id}')">${sv(ic,19)}<span>${t(l)}</span></button>`).join('')}
function tab(id){curTab=id;TABS.forEach(([x])=>{$('tab-'+x).classList.toggle('on',x===id);$('v-'+x).classList.toggle('on',x===id)});
  const T=TABS.find(x=>x[0]===id);$('pg-title').textContent=t(T[1]==='navHome'?'app':T[1]);$('pg-sub').textContent=t(T[2]);
  if(id==='setup')loadWifi();if(id==='settings')renderPw();if(id==='energy')loadEnergy();render();window.scrollTo(0,0)}
function applyLang(){
  const h=document.documentElement;h.lang=LANG;h.dir=LANG==='ar'?'rtl':'ltr';document.title=t('app');
  document.querySelectorAll('[data-t]').forEach(e=>e.textContent=t(e.dataset.t));
  document.querySelectorAll('[data-th]').forEach(e=>e.innerHTML=t(e.dataset.th));
  document.querySelectorAll('[data-tp]').forEach(e=>e.placeholder=t(e.dataset.tp));
  $('lang-btn').innerHTML=sv(P.globe,15)+(LANG==='ar'?'English':'العربية');
  $('new-rule').textContent=t('newRule');
  segSet('lang-seg',LANG);
  buildNav();buildDays();buildQuick();buildPick();$('xl-ico').innerHTML=sv('<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',15);
  const T=TABS.find(x=>x[0]===curTab);$('pg-title').textContent=t(T[1]==='navHome'?'app':T[1]);$('pg-sub').textContent=t(T[2]);
}
async function setLang(l){if(l===LANG)return;LANG=l;applyLang();render();renderLog();if(curTab==='energy')drawEnergy();if(curTab==='settings')renderPw();
  try{await api('/api/lang',{lang:LANG})}catch(e){}refresh()}
function switchLang(){setLang(LANG==='ar'?'en':'ar')}

/* ---------------- state ---------------- */
async function refresh(){
  try{S=await getJSON('/api/state')}catch(e){$('dot').className='dot';$('stxt').textContent=t('appOff');return}
  const on=S.devices.filter(d=>d.online).length,all=S.devices.length;
  $('dot').className='dot'+(on?' ok':'');$('stxt').textContent=all?t('connOf',on,all):t('connNone');
  const w=$('ipwarn');
  if(S.provisioned_ip&&S.current_ip&&S.provisioned_ip!==S.current_ip&&!S.setup.running){w.style.display='block';w.innerHTML=t('ipWarn','<span class="ltr">'+esc(S.current_ip)+'</span>','<span class="ltr">'+esc(S.provisioned_ip)+'</span>')}
  else w.style.display='none';
  render();renderLog();
}
function render(){if(!S||editing)return;if(curTab==='home')renderHome();if(curTab==='sched')renderSched();if(curTab==='energy'&&Date.now()-EN_AT>60000&&(EN.mode!=='custom'))loadEnergy()}

/* ---------------- home ---------------- */
let VIEW=(()=>{try{return localStorage.getItem('mttl_view')||'strip'}catch(e){return 'strip'}})();
function setView(v){VIEW=v;try{localStorage.setItem('mttl_view',v)}catch(e){}renderHome()}
function allRooms(){const r=new Set();S.devices.forEach(d=>d.outlets.forEach(o=>o.room&&r.add(o.room)));return [...r].sort((a,b)=>a.localeCompare(b,LANG))}

function renderHome(){
  const box=$('devices'),sum=$('summary'),bar=$('toolbar');
  if(!S.devices.length){
    sum.innerHTML='';bar.innerHTML='';
    box.innerHTML=`<div class="panel empty">${sv(TYPE_P.other,44)}<h2>${t('emptyTitle')}</h2><p>${t('emptyText')}</p>
      <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap"><button class="btn primary" onclick="tab('setup')">${sv(P.plus,17)}${t('addStrip')}</button>${S.provisioned_ip?`<button class="btn" onclick="tab('settings');runDiag()">${t('scanNet')}</button>`:''}</div></div>`;
    return;
  }
  const online=S.devices.filter(d=>d.online), W=online.reduce((a,d)=>a+d.total_w,0), live=online.reduce((a,d)=>a+d.outlets.filter(o=>o.on).length,0);
  sum.innerHTML=`<div class="summary">
    <div class="sum main-w"><span class="lbl">${t('drawNow')}</span><b class="ltr">${W.toFixed(1)}<small>W</small></b></div>
    <div class="sum"><span class="lbl">${t('outletsOn')}</span><b>${live}<small>/ ${online.length*4}</small></b></div>
    <div class="sum"><span class="lbl">${t('todayUse')}</span><b>${kwh(S.today_wh)}<small>kWh</small></b>${S.price_kwh?`<span class="sub">${money(S.today_wh)}</span>`:''}</div>
    <div class="sum"><span class="lbl">${t('activeSched')}</span><b>${S.schedules.filter(r=>r.enabled).length}</b></div>
    <div class="sum sum-acts"><button class="btn primary sm" onclick="tab('setup')">${sv(P.plus,16)}${t('addStrip')}</button>
      ${online.length?`<div class="pair"><button class="btn sm" onclick="allHouse(true)">${t('allOn')}</button><button class="btn sm danger" onclick="allHouse(false)">${t('allOff')}</button></div>`:''}</div>
  </div>`;
  bar.innerHTML=`<div class="seg"><button class="${VIEW==='strip'?'on':''}" onclick="setView('strip')">${t('byStrip')}</button><button class="${VIEW==='room'?'on':''}" onclick="setView('room')">${t('byRoom')}</button></div>`+
    (VIEW==='room'&&!allRooms().length?`<span class="hint" style="margin:0">${t('roomHint')}</span>`:'');
  box.innerHTML=VIEW==='room'?roomsHTML():S.devices.map(stripHTML).join('');
}

function stripHTML(d){
  const meta=d.online
    ?`<span class="pill ok"><i></i>${t('online')}</span><span class="ltr">${esc(d.ip)}</span>`
    :`<span class="pill"><i></i>${t('offAgo',ago(d.last_seen))}</span><button class="link" onclick="tab('settings');runDiag()">${t('whyMissing')}</button><button class="link" onclick="forget('${d.mac}')">${t('remove')}</button>`;
  return `<section class="strip${d.online?'':' is-off'}">
    <header class="strip-h"><div class="strip-id">
      <input class="strip-name" value="${esc(d.label)}" aria-label="${t('stripName')}" onfocus="editing=true" onblur="editing=false;rename('${d.mac}','strip',this.value)" onkeydown="if(event.key==='Enter')this.blur()">
      <div class="meta">${meta}</div></div>
      ${d.online?`<div class="strip-w"><b class="ltr">${d.has_data?d.total_w.toFixed(1):'—'}<small>W</small></b><span>${t('stripDraw')}</span></div>`:''}
    </header>
    <div class="bar">${d.outlets.map(o=>slotHTML(d,o)).join('')}</div>
    ${d.online?`<footer class="strip-f"><button class="btn ghost sm" onclick="all_('${d.mac}',true)">${t('stripOn')}</button><button class="btn ghost sm danger" onclick="all_('${d.mac}',false)">${t('stripOff')}</button></footer>`:''}
  </section>`;
}
function infoHTML(d,o){
  let h='';
  if(o.timer)h+=`<div class="chip-i t"><span>${sv(P.timer,13)} ${t(o.timer.action==='off'?'offIn':'onIn','<span class="ltr">'+fmtLeft(o.timer.left)+'</span>')}</span><button class="link" onclick="cancelTimer('${d.mac}',${o.n})">${t('cancelIt')}</button></div>`;
  if(o.next)h+=`<div class="chip-i s"><span>${sv(P.cal,13)} ${t(o.next.action==='on'?'nextOn':'nextOff',whenText(o.next.at))}</span></div>`;
  if(o.pending)h+=`<div class="chip-i t"><span>${t('queued')}</span></div>`;
  if(o.autooff&&o.on)h+=`<div class="chip-i c"><span>${sv(TYPE_P.charger,13)} ${o.autooff.left!=null?t('aoCount','<span class="ltr">'+fmtLeft(o.autooff.left)+'</span>'):o.autooff.armed?t('aoWatch'):t('aoWait')}</span></div>`;
  return h;
}
function slotHTML(d,o){
  const k=d.mac+o.n,dis=!d.online,st=dis?'na':o.on?'on':'off';
  const sub=[o.type?typeLabel(o.type):'',o.room].filter(Boolean).join(t('sep'));
  return `<div class="slot ${st}">
    <button class="s-head" onclick="openOutlet('${d.mac}',${o.n})" title="${t('editOutlet')}"><span class="n">${o.n}</span><span class="nm">${esc(o.name)}</span><span class="ed">${sv(P.pencil,14)}</span></button>
    <div class="s-sub">${o.type?sv(TYPE_P[o.type],14):''}${sub?`<span>${esc(sub)}</span>`:(o.named?'':`<button class="link" onclick="openOutlet('${d.mac}',${o.n})">${t('setAppliance')}</button>`)}</div>
    <button class="socket" ${busy[k]||dis?'disabled':''} aria-pressed="${o.on}" aria-label="${esc(o.name)}" onclick="toggle('${d.mac}',${o.n},${!o.on})"><span class="ring"></span></button>
    <div class="s-state">${t(st==='na'?'stNa':st==='on'?'stOn':'stOff')}</div>
    ${o.fault?`<div class="fault">${t(o.fault)}</div>`:''}
    ${d.has_data?`<div class="reads"><span><b class="ltr">${o.on?o.power_w.toFixed(1):'0'}</b> W</span><span><b class="ltr">${kwh(o.today_wh)}</b> ${t('kwhToday')}</span></div>`:''}
    ${infoHTML(d,o)}
    <div class="s-acts"><button class="ibtn" ${dis?'disabled':''} onclick="openTimer('${d.mac}',${o.n})">${sv(P.timer,14)}${t('timer')}</button><button class="ibtn" onclick="openRule(null,[['${d.mac}',${o.n}]])">${sv(P.cal,14)}${t('schedule')}</button></div>
  </div>`;
}
let ROOM_GROUPS=[];
function roomsHTML(){
  const g={};S.devices.forEach(d=>d.outlets.forEach(o=>{(g[o.room]=g[o.room]||[]).push([d,o])}));
  const names=Object.keys(g).sort((a,b)=>a===''?1:b===''?-1:a.localeCompare(b,LANG));
  ROOM_GROUPS=[];
  return names.map(r=>{
    const list=g[r],on=list.filter(([d])=>d.online),W=on.reduce((a,[d,o])=>a+(o.on?o.power_w:0),0),label=r||t('roomNone');
    const gi=ROOM_GROUPS.push({targets:on.map(([d,o])=>[d.mac,o.n]),label})-1;
    return `<section class="room"><div class="room-h"><div><h3>${esc(label)}</h3><small>${t('outletsCount',list.length,list.filter(([d,o])=>d.online&&o.on).length)}</small></div>
      <div class="acts"><span class="w ltr">${W.toFixed(1)} W</span>${on.length?`<button class="btn ghost sm" onclick="roomSet(${gi},true)">${t('roomOn')}</button><button class="btn ghost sm danger" onclick="roomSet(${gi},false)">${t('roomOff')}</button>`:''}</div></div>
      ${list.map(([d,o])=>{const k=d.mac+o.n,dis=!d.online,st=dis?'na':o.on?'on':'off';
        return `<div class="row ${st}"><div class="ico">${tIco(o.type,20)}</div>
          <div class="tx"><b><button class="link" style="font-size:inherit;color:inherit;text-decoration:none" onclick="openOutlet('${d.mac}',${o.n})">${esc(o.name)}</button></b><small>${t('outletOf',esc(d.label),o.n)}${dis?' '+t('offlineTag'):''}</small>${o.timer||o.next||(o.autooff&&o.on)?`<div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:5px">${infoHTML(d,o)}</div>`:''}</div>
          <div class="rd">${d.has_data?`<b class="ltr">${o.on?o.power_w.toFixed(1):'0'} W</b>${kwh(o.today_wh)} ${t('kwhToday')}`:''}</div>
          <button class="pilot" ${busy[k]||dis?'disabled':''} aria-pressed="${o.on}" aria-label="${esc(o.name)}" onclick="toggle('${d.mac}',${o.n},${!o.on})"></button></div>`}).join('')}
    </section>`;
  }).join('');
}
function roomSet(i,on){const g=ROOM_GROUPS[i];if(g)groupSet(g.targets,on,g.label)}
async function groupSet(targets,on,label){if(!on&&!confirm(t('confirmGroupOff',label)))return;try{await api('/api/group',{targets,on,label})}catch(e){toast(e.message,1)}setTimeout(refresh,900)}
async function toggle(mac,n,on){const k=mac+n;busy[k]=1;renderHome();try{await api('/api/outlet',{mac,n,on})}catch(e){toast(e.message,1)}delete busy[k];setTimeout(refresh,600)}
async function all_(mac,on){try{await api('/api/all',{mac,on})}catch(e){toast(e.message,1)}setTimeout(refresh,900)}
async function allHouse(on){if(!on&&!confirm(t('confirmHouseOff')))return;all_('*',on)}
async function rename(mac,key,name){try{await api('/api/name',{mac,key,name})}catch(e){toast(e.message,1)}refresh()}
async function cancelTimer(mac,n){try{await api('/api/timer',{mac,n,mode:'cancel'})}catch(e){toast(e.message,1)}refresh()}
async function forget(mac){if(!confirm(t('confirmForget')))return;try{await api('/api/forget',{mac})}catch(e){toast(e.message,1)}refresh()}

/* ---------------- dialogs ---------------- */
function openM(id){$(id).classList.add('on');const f=$(id).querySelector('input[type=text],input[type=number]');if(f&&innerWidth>560)setTimeout(()=>f.focus(),30)}
function closeM(id){$(id).classList.remove('on')}
function segVal(id){return $(id).querySelector('.on').dataset.v}
function segSet(id,v){$(id).querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.v===v))}
function segBind(id,cb){$(id).querySelectorAll('button').forEach(b=>b.addEventListener('click',()=>{segSet(id,b.dataset.v);cb&&cb(b.dataset.v)}))}
document.addEventListener('keydown',e=>{if(e.key==='Escape')['m-timer','m-rule','m-outlet'].forEach(closeM)});

let OL={};
function openOutlet(mac,n){
  const d=S.devices.find(x=>x.mac===mac),o=d.outlets[n-1];OL={mac,n,type:o.type||''};
  $('ol-for').textContent=t('olFor',d.label,n);
  $('ol-name').value=o.named?o.name:'';$('ol-room').value=o.room||'';
  renderTypes();
  const rooms=[...new Set([...allRooms(),...t('rooms')])];
  $('rooms-dl').innerHTML=rooms.map(r=>`<option value="${esc(r)}">`).join('');
  $('ol-rooms').innerHTML=rooms.slice(0,10).map(r=>`<button class="chip" onclick="$('ol-room').value=this.textContent">${esc(r)}</button>`).join('');
  const ao=o.autooff;$('ao-on').checked=!!ao;$('ao-f').style.display=ao?'grid':'none';$('ao-w').value=ao?ao.w:5;$('ao-m').value=ao?ao.min:5;
  $('ol-err').textContent='';openM('m-outlet');
}
function renderTypes(){$('ol-types').innerHTML=Object.keys(TYPE_P).map(k=>`<button class="${OL.type===k?'on':''}" onclick="pickType('${k}')">${sv(TYPE_P[k],20)}${typeLabel(k)}</button>`).join('')}
function pickType(k){const nm=$('ol-name'),prev=OL.type?typeLabel(OL.type):'';OL.type=OL.type===k?'':k;renderTypes();
  if(OL.type&&(!nm.value.trim()||nm.value===prev))nm.value=typeLabel(OL.type);
  if(OL.type==='charger'&&!$('ao-on').checked){$('ao-on').checked=true;$('ao-f').style.display='grid'}}
async function saveOutlet(){try{await api('/api/outlet_meta',{mac:OL.mac,n:OL.n,name:$('ol-name').value,type:OL.type,room:$('ol-room').value});
  await api('/api/autooff',{mac:OL.mac,n:OL.n,enabled:$('ao-on').checked,w:+$('ao-w').value,min:+$('ao-m').value});closeM('m-outlet');refresh()}catch(e){$('ol-err').textContent=e.message}}

let T={};
function openTimer(mac,n){const d=S.devices.find(x=>x.mac===mac),o=d.outlets[n-1];T={mac,n};
  $('t-for').textContent=d.label+t('sep')+o.n+' — '+o.name;segSet('t-mode',o.on?'off_after':'run_for');
  $('t-h').value=0;$('t-m').value=30;$('t-err').textContent='';openM('m-timer');timerPrev()}
function buildQuick(){$('t-quick').innerHTML=[[15,'q15'],[30,'q30'],[60,'q60'],[120,'q120'],[240,'q240'],[480,'q480']].map(([m,k])=>`<button class="chip" onclick="$('t-h').value=${Math.floor(m/60)};$('t-m').value=${m%60};timerPrev()">${t(k)}</button>`).join('')}
['t-h','t-m'].forEach(i=>$(i).addEventListener('input',timerPrev));
const timerMin=()=>(+$('t-h').value||0)*60+(+$('t-m').value||0);
function timerPrev(){const mins=timerMin(),mode=segVal('t-mode');if(mins<=0){$('t-prev').textContent=t('needMin');return}
  const at=new Date(Date.now()+mins*60000),w=t('at',dayWord(at),clockOf(at));
  $('t-prev').textContent=t(mode==='run_for'?'pvRun':mode==='off_after'?'pvOff':'pvOn',w)}
async function saveTimer(){const minutes=timerMin();if(minutes<=0){$('t-err').textContent=t('needMin');return}
  try{await api('/api/timer',{mac:T.mac,n:T.n,mode:segVal('t-mode'),minutes});closeM('m-timer');refresh()}catch(e){$('t-err').textContent=e.message}}

let R={id:null,days:[]};
function buildDays(){$('r-days').innerHTML=dayOrder().map(d=>`<button class="chip${(R.days||[]).includes(d)?' on':''}" data-d="${d}" onclick="flipDay(${d})">${t('days')[d]}</button>`).join('')}
function setDays(a){R.days=[...a];$('r-days').querySelectorAll('.chip').forEach(c=>c.classList.toggle('on',R.days.includes(+c.dataset.d)))}
function flipDay(d){setDays(R.days.includes(d)?R.days.filter(x=>x!==d):[...R.days,d])}
function openRule(id,preset){
  const r=id?S.schedules.find(x=>x.id===id):null;R={id:r?r.id:null,days:[]};
  $('r-title').textContent=t(r?'editRule':'newRule').replace('+ ','');
  $('r-name').value=r?r.name:'';segSet('r-act',r?r.action:'on');$('r-time').value=r?r.time:'07:00';
  const once=!!(r&&r.once_date);segSet('r-rep',once?'once':'days');showRep();
  const now=new Date();$('r-date').value=r&&r.once_date?r.once_date:now.getFullYear()+'-'+two(now.getMonth()+1)+'-'+two(now.getDate());
  setDays(r&&!once?r.days:[0,1,2,3,4,5,6]);
  const dur=r?r.duration_min:0;$('r-dur-on').checked=!!dur;$('r-dur').style.display=dur?'grid':'none';
  $('r-dh').value=dur?Math.floor(dur/60):1;$('r-dm').value=dur?Math.round(dur%60):0;showDur();
  const sel=(r?r.targets:(preset||[])).map(x=>x[0]+':'+x[1]),rms=allRooms();
  $('r-targets').innerHTML=(rms.length?`<div class="chips" style="margin:0 0 4px;align-items:center"><span class="hint" style="margin:0">${t('pickRoom')}</span>${rms.map(x=>`<button class="chip" onclick="pickRoom(this.textContent)">${esc(x)}</button>`).join('')}</div>`:'')+
    (S.devices.length?S.devices.map(d=>`<div class="tg-strip"><div class="h"><span>${esc(d.label)} ${d.online?'':`<small class="hint">${t('offlineTag')}</small>`}</span><button class="link" onclick="this.closest('.tg-strip').querySelectorAll('input').forEach(i=>i.checked=true)">${t('allOutlets')}</button></div><div class="tg-grid">`+
      d.outlets.map(o=>`<label><input type="checkbox" value="${d.mac}:${o.n}" ${sel.includes(d.mac+':'+o.n)?'checked':''}><span>${o.n}. ${esc(o.name)}</span></label>`).join('')+'</div></div>').join(''):`<p class="hint">${t('connectFirst')}</p>`);
  $('r-err').textContent='';openM('m-rule');
}
function showRep(){const o=segVal('r-rep')==='once';$('r-once-box').style.display=o?'block':'none';$('r-days-box').style.display=o?'none':'block'}
function showDur(){$('r-dur-box').style.display=segVal('r-act')==='on'?'block':'none'}
segBind('r-rep',showRep);segBind('r-act',showDur);segBind('t-mode',timerPrev);
function pickRoom(r){const keys=[];S.devices.forEach(d=>d.outlets.forEach(o=>{if(o.room===r)keys.push(d.mac+':'+o.n)}));
  $('r-targets').querySelectorAll('input').forEach(i=>{if(keys.includes(i.value))i.checked=true});if(!$('r-name').value)$('r-name').value=r}
async function saveRule(){
  const once=segVal('r-rep')==='once',action=segVal('r-act'),durOn=action==='on'&&$('r-dur-on').checked;
  const body={id:R.id,name:$('r-name').value,action,time:$('r-time').value,days:once?[]:R.days,once_date:once?$('r-date').value:null,
    duration_min:durOn?(+$('r-dh').value||0)*60+(+$('r-dm').value||0):0,
    targets:[...$('r-targets').querySelectorAll('input:checked')].map(i=>{const [m,n]=i.value.split(':');return [m,+n]}),enabled:true};
  if(durOn&&body.duration_min<=0){$('r-err').textContent=t('needDur');return}
  try{await api('/api/schedule',body);closeM('m-rule');refresh()}catch(e){$('r-err').textContent=e.message}
}

/* ---------------- schedules ---------------- */
function renderSched(){
  const R_=S.schedules;
  $('rules').innerHTML=R_.length?`<div class="panel rules">${R_.map(r=>{
    const [h,m]=r.time.split(':').map(Number);
    const tag=r.action==='on'?`<span class="tag on">${r.duration_min?t('ruleOnFor',durText(r.duration_min)):t('ruleOn')}</span>`:`<span class="tag off">${t('ruleOff')}</span>`;
    const sub=[daysText(r)];if(r.enabled&&r.next)sub.push(t('nextAt',whenText(r.next)));
    return `<div class="rule${r.enabled?'':' dis'}">
      <div class="r-time"><b>${(h%12||12)+':'+two(m)}</b><small>${h<12?t('morning'):t('evening')}</small></div>
      <div><div class="r-title">${esc(r.name||t('unnamed'))} ${tag}</div><div class="r-sub">${sub.join(t('sep'))}</div>
        <div class="r-tg">${r.target_labels.map(x=>`<span>${esc(x)}</span>`).join('')}</div></div>
      <div class="r-side"><label class="switch" title="${t('edit')}"><input type="checkbox" ${r.enabled?'checked':''} onchange="toggleRule('${r.id}',this.checked)"><span></span></label>
        <div class="r-btns"><button title="${t('edit')}" aria-label="${t('edit')}" onclick="openRule('${r.id}')">${sv(P.pencil,17)}</button><button title="${t('runNow')}" aria-label="${t('runNow')}" onclick="runRule('${r.id}')">${sv(P.play,17)}</button><button title="${t('del')}" aria-label="${t('del')}" onclick="delRule('${r.id}')">${sv(P.trash,17)}</button></div></div>
    </div>`}).join('')}</div>`
    :`<div class="panel empty">${sv(P.cal,42)}<h2>${t('noRules')}</h2><p>${t('noRulesText')}</p><button class="btn primary" onclick="openRule()">${t('newRule')}</button></div>`;
  $('events').innerHTML=S.events.length?S.events.map(e=>{const d=new Date(e.ts*1000);return `<div class="ev ${e.kind}"><time>${two(d.getHours())}:${two(d.getMinutes())}</time><span>${esc(e.text)}</span></div>`}).join(''):`<p class="hint">${t('noEvents')}</p>`;
}
async function toggleRule(id,enabled){try{await api('/api/schedule/toggle',{id,enabled})}catch(e){toast(e.message,1)}refresh()}
async function delRule(id){if(!confirm(t('confirmDel')))return;try{await api('/api/schedule/delete',{id})}catch(e){toast(e.message,1)}refresh()}
async function runRule(id){try{await api('/api/schedule/run',{id});toast(t('done'))}catch(e){toast(e.message,1)}setTimeout(refresh,800)}

/* ---------------- energy ---------------- */
const isoD=d=>d.getFullYear()+'-'+two(d.getMonth()+1)+'-'+two(d.getDate());
let EN={mode:'week',day:isoD(new Date()),from:'',to:'',sel:null,group:'app',data:null},EN_AT=0;
(()=>{const t0=new Date(),a=new Date(t0);a.setDate(a.getDate()-29);EN.from=isoD(a);EN.to=isoD(t0)})();
segBind('en-mode',v=>{EN.mode=v;EN.sel=null;buildPick();loadEnergy()});
segBind('en-group',v=>{EN.group=v;EN.sel=null;drawEnergy()});
function buildPick(){
  const p=$('en-pick'),today=isoD(new Date());
  if(EN.mode==='day')p.innerHTML=`<button class="nav-d" onclick="shiftDay(-1)" aria-label="-1">${sv(LANG==='ar'?'<path d="M9 6l6 6-6 6"/>':'<path d="M15 6l-6 6 6 6"/>',16)}</button><input type="date" id="en-day" class="ltr" value="${EN.day}" max="${today}" onchange="EN.day=this.value;loadEnergy()"><button class="nav-d" onclick="shiftDay(1)" ${EN.day>=today?'disabled':''} aria-label="+1">${sv(LANG==='ar'?'<path d="M15 6l-6 6 6 6"/>':'<path d="M9 6l6 6-6 6"/>',16)}</button>`;
  else if(EN.mode==='custom')p.innerHTML=`<span class="hint" style="margin:0">${t('from')}</span><input type="date" class="ltr" value="${EN.from}" max="${today}" onchange="EN.from=this.value;loadEnergy()"><span class="hint" style="margin:0">${t('to')}</span><input type="date" class="ltr" value="${EN.to}" max="${today}" onchange="EN.to=this.value;loadEnergy()">`;
  else p.innerHTML='';
}
function shiftDay(k){const d=new Date(EN.day+'T12:00');d.setDate(d.getDate()+k);const s=isoD(d);if(s>isoD(new Date()))return;EN.day=s;buildPick();loadEnergy()}
function enQuery(){return 'mode='+EN.mode+(EN.mode==='day'?'&day='+EN.day:'')+(EN.mode==='custom'?'&from='+EN.from+'&to='+EN.to:'')}
async function loadEnergy(){EN_AT=Date.now();try{EN.data=await getJSON('/api/energy?'+enQuery())}catch(e){return}drawEnergy()}
function exportXlsx(){location.href='/api/energy.xlsx?'+enQuery()}
function bucketLabel(k,kind,full){
  const loc=LANG==='ar'?'ar-EG-u-nu-latn':'en-GB';
  if(kind==='hour'){const h=+k.slice(-2);return full?clock(h,0):String(h)}
  if(kind==='month'){const d=new Date(k+'-01T12:00');return d.toLocaleDateString(loc,full?{month:'long',year:'numeric'}:{month:'short'})}
  const d=new Date(k+'T12:00');
  if(full)return d.toLocaleDateString(loc,{weekday:'long',day:'numeric',month:'long'});
  return EN.data.keys.length<=7?t('dShort')[(d.getDay()+6)%7]:d.getDate()+'/'+(d.getMonth()+1);
}
function groups(E){
  if(EN.group==='app')return E.items.map(it=>({key:it.mac+':'+it.n,name:it.name,sub:it.room||it.strip,type:it.type,buckets:it.buckets,total:it.total}));
  const g={};E.items.forEach(it=>{const k=it.room||'';const x=g[k]=g[k]||{key:'room:'+k,name:k||t('roomNone'),sub:'',type:null,buckets:it.buckets.map(()=>0),total:0};
    it.buckets.forEach((v,i)=>x.buckets[i]+=v);x.total+=it.total;x.sub=(x.sub?x.sub+t('sep'):'')+it.name});
  return Object.values(g).sort((a,b)=>b.total-a.total);
}
function drawEnergy(){
  const E=EN.data;if(!E)return;
  const price=E.price||0,cost=wh=>price?(wh/1000*price).toFixed(2)+' '+t('egp'):'';
  if(document.activeElement!==$('en-price'))$('en-price').value=price||'';
  const G=groups(E),sel=EN.sel&&G.find(g=>g.key===EN.sel);if(EN.sel&&!sel)EN.sel=null;
  const series=sel?sel.buckets:E.totals,total=sel?sel.total:E.total,n=series.length;
  const today=isoD(new Date());
  let used=n;if(E.kind==='day'&&E.end>today)used=E.keys.filter(k=>k<=today).length;
  if(E.kind==='hour'&&E.start===today)used=new Date().getHours()+1;
  const avg=total/Math.max(1,used),peakI=series.indexOf(Math.max(...series));
  const prevName={day:E.start===today?'prevDay':'prevOtherDay',week:'prevWeek',month:'prevMonth',year:'prevYear',custom:'prevCustom'}[E.mode];
  let cmp='';
  if(!sel&&E.prev_total){const d=(E.total-E.prev_total)/E.prev_total,pc=Math.round(Math.abs(d)*100);
    cmp=pc<2?`<span class="cmp flat">${t('vsPrev',t('same'),t(prevName))}</span>`:`<span class="cmp ${d>0?'up':'down'}">${d>0?'▲':'▼'} ${pc}% ${t('vsPrev',t(d>0?'more':'less'),t(prevName))}</span>`}
  const avgK={hour:'avgHour',day:'avgDay2',month:'avgMonth'}[E.kind],peakK={hour:'peakHour',day:'peakDay',month:'peakMonth'}[E.kind];
  $('en-k').innerHTML=`<div class="kpi"><span class="lbl">${t('enTotal')}</span><b class="ltr">${kwh(total)}<small>kWh</small></b>${price?`<span class="hint" style="display:block;margin:0">${cost(total)}</span>`:''}${cmp?'<div>'+cmp+'</div>':''}</div>
    <div class="kpi"><span class="lbl">${t(avgK)}</span><b class="ltr">${kwh(avg)}<small>kWh</small></b></div>
    ${total?`<div class="kpi"><span class="lbl">${t(peakK)}</span><b style="font-size:17px">${bucketLabel(E.keys[peakI],E.kind,true)}</b><span class="hint" style="display:block;margin:0">${kwh(series[peakI])} kWh</span></div>`:''}`;
  $('en-ttl').textContent=sel?sel.name:t('allDevices');$('en-clear').style.display=sel?'':'none';
  const max=Math.max(1,...series),showVal=n<=8;
  $('en-bars').innerHTML=total?series.map((v,i)=>`<div class="col${i===peakI&&v?' peak':''}${(E.kind==='hour'&&E.start===today&&i===new Date().getHours())||(E.kind==='day'&&E.keys[i]===today)?' today':''}" title="${esc(bucketLabel(E.keys[i],E.kind,true))}: ${kwh(v)} kWh${price?' — '+cost(v):''}">${showVal&&v?`<b>${kwh(v)}</b>`:''}<i style="height:${v/max*100}%"></i></div>`).join('')
    :`<p class="hint" style="align-self:center;margin:auto">${t('noData')}${E.kind==='hour'?' '+t('hourNoteOld'):''}</p>`;
  const step=n<=8?1:n<=12?1:n<=24?3:n<=31?5:Math.ceil(n/8);
  $('en-lbl').innerHTML=E.keys.map((k,i)=>`<span>${i%step===0||i===n-1?bucketLabel(k,E.kind,false):''}</span>`).join('');
  const top=Math.max(1,...G.map(g=>g.total));
  $('en-items').innerHTML=G.length?G.map(g=>`<div class="ap${EN.sel===g.key?' sel':EN.sel?' dim':''}" onclick="EN.sel=EN.sel==='${esc(g.key)}'?null:'${esc(g.key)}';drawEnergy()"><div class="ico">${g.type!==null?tIco(g.type,20):sv(P.home,20)}</div>
      <div class="tx" style="min-width:0"><b>${esc(g.name)}</b><small>${esc(g.sub)}</small><div class="meter"><i style="width:${g.total/top*100}%"></i></div></div>
      <div class="v"><b class="ltr">${kwh(g.total)} kWh</b><small>${cost(g.total)||(E.total?Math.round(g.total/E.total*100)+'%':'')}</small></div></div>`).join('')
    :`<p class="hint">${t('noReadings')}</p>`;
}
async function savePrice(){try{await api('/api/price',{price:+$('en-price').value||0});toast(t('savedPrice'));await refresh();loadEnergy()}catch(e){toast(e.message,1)}}

/* ---------------- setup ---------------- */
async function loadWifi(){
  try{const w=await getJSON('/api/wifi'),onSetup=/^T?ONLY_TAP_/i.test(w.current_ssid||'');
    if(!$('ssid').value)$('ssid').value=w.current_ssid&&!onSetup?w.current_ssid:(w.saved_home_ssid||'');
    if(!$('hip').value&&w.current_ssid&&!onSetup)$('hip').value=w.current_ip||'';
    if(!$('hip').value)$('hip').value=(S&&S.provisioned_ip)||w.current_ip||'';
    $('aplist').innerHTML=w.setup_networks.length?t('apFound')+w.setup_networks.map(x=>`<code>${esc(x)}</code>`).join(' '):'';
  }catch(e){}
  if(S&&!S.is_windows){$('auto').checked=false;$('autorow').style.display='none'}
}
async function startSetup(){const body={ssid:$('ssid').value.trim(),password:$('pwd').value,home_ip:$('hip').value.trim(),auto_wifi:$('auto').checked};
  try{await api('/api/setup',body);$('go').disabled=true;setTimeout(refresh,500)}catch(e){toast(e.message,1)}}
function renderLog(){if(!S)return;const st=S.setup;$('go').disabled=st.running;$('go').textContent=st.running?t('setupBusy'):st.result==='error'?t('retry'):t('goSetup');
  $('log').innerHTML=st.steps.map(x=>`<div class="${x.kind}"><time>${x.t}</time>${esc(x.text)}</div>`).join('')}

/* ---------------- settings ---------------- */
async function runDiag(){
  const b=$('diag-go'),box=$('diag');b.disabled=true;b.textContent=t('diagBusy');box.innerHTML='';
  try{const d=await getJSON('/api/diag');let h='<div class="dg">';
    h+=`<div class="dg-row ${d.ip_ok?'online good':'on_lan'}"><div class="t"><span>${t('pcAddr')}</span><small class="ltr">${esc(d.laptop_ip||'?')}</small></div><p>${!d.provisioned_ip?t('noProv'):d.ip_ok?t('ipOk'):t('ipBad','<span class="ltr">'+esc(d.provisioned_ip)+'</span>')}</p></div>`;
    const st={online:'dOnline',on_lan:'dOnLan',missing:'dMissing'};
    h+=d.strips.map(x=>`<div class="dg-row ${x.status}${x.status==='online'?' good':''}"><div class="t"><span>${esc(x.label)}: ${t(st[x.status])}</span><small class="ltr">${esc(x.lan_ip||x.mac)}</small></div><p>${esc(x.advice)}${x.status==='on_lan'&&!d.ip_ok?` <button class="link" onclick="tab('setup')">${t('setupAgain')}</button>`:''}</p></div>`).join('');
    h+=d.unknown.map(x=>`<div class="dg-row on_lan"><div class="t"><span>${t('maybeNew')}</span><small class="ltr">${esc(x.ip)}</small></div><p>${t('maybeNewText','<span class="ltr">'+esc(x.mac)+'</span>')}</p></div>`).join('');
    if(!d.strips.length&&!d.unknown.length)h+=`<div class="dg-row missing"><div class="t"><span>${t('noStrips')}</span></div><p>${t('noStripsText')}</p></div>`;
    box.innerHTML=h+`<p class="hint">${t('scanned',d.devices_seen)}</p></div>`;
  }catch(e){box.innerHTML=`<div class="err">${t('diagFail',esc(e.message))}</div>`}
  b.disabled=false;b.textContent=t('diagAgain');
}
function renderPw(){const on=S&&S.auth_enabled;$('pw-state').textContent=on?t('pwOn'):t('pwNone');
  $('pw-off').style.display=on?'':'none';$('pw-logout').style.display=on?'':'none';$('pw-err').textContent='';
  if(!$('diag').innerHTML)$('diag-go').textContent=t('diagGo')}
async function savePw(){const a=$('pw1').value,b=$('pw2').value;
  if(a.length<6){$('pw-err').textContent=t('pwShort');return}if(a!==b){$('pw-err').textContent=t('pwMismatch');return}
  try{await api('/api/password',{password:a});$('pw1').value=$('pw2').value='';await refresh();renderPw();toast(t('pwSaved'))}catch(e){$('pw-err').textContent=e.message}}
async function clearPw(){if(!confirm(t('pwConfirmOff')))return;try{await api('/api/password',{password:''});await refresh();renderPw()}catch(e){toast(e.message,1)}}
async function logout(){await api('/api/logout',{});location.reload()}
segBind('lang-seg',v=>setLang(v));

applyLang();$('diag-go').textContent=t('diagGo');refresh();loadWifi();setInterval(refresh,2000);
</script>
</body>
</html>
"""

LOGIN_PAGE = r"""<!DOCTYPE html>
<html lang="__LANG__" dir="__DIR__"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<link href="https://fonts.googleapis.com/css2?family=Readex+Pro:wght@400;500;600&display=swap" rel="stylesheet">
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0e141c;color:#e8eef5;padding:16px;box-sizing:border-box;font-family:"Readex Pro",Tahoma,sans-serif}
form{width:100%;max-width:360px;background:#16202b;border:1px solid #253242;border-radius:20px;padding:28px}
.logo{width:46px;height:46px;border-radius:13px;background:#e0a458;display:grid;place-items:center;color:#1d1408;margin-bottom:16px}
h1{margin:0 0 4px;font-size:21px;font-weight:600}p{margin:0 0 20px;color:#8b9aae;font-size:14px}
input{width:100%;box-sizing:border-box;background:#0c1118;border:1px solid #253242;color:#e8eef5;border-radius:11px;padding:12px;font:inherit;font-size:16px}
input:focus{outline:none;border-color:#e0a458}
button{width:100%;margin-top:12px;background:#e0a458;color:#1d1408;border:0;border-radius:12px;padding:12px;font:inherit;font-weight:600;font-size:15px;cursor:pointer}
.err{color:#ffaaaa;font-size:13px;margin-top:10px;min-height:18px}
</style></head><body>
<form onsubmit="go(event)">
  <div class="logo"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 4 14h7l-1 8 9-12h-7z"/></svg></div>
  <h1>__TITLE__</h1><p>__LEAD__</p>
  <input type="password" id="pw" autofocus autocomplete="current-password" placeholder="__PH__">
  <button>__BTN__</button><div class="err" id="err"></div>
</form>
<script>
async function go(e){e.preventDefault();const err=document.getElementById('err');err.textContent='';
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('pw').value})});
  if(r.ok){location.reload();return}let j={};try{j=await r.json()}catch(x){}err.textContent=j.error||'Error'}
</script></body></html>
"""


def page_html():
    lang = CFG.get("lang", "ar")
    return PAGE.replace("__LANG__", lang).replace("__DIR__", "ltr" if lang == "en" else "rtl")


def login_html():
    en = CFG.get("lang") == "en"
    return (LOGIN_PAGE.replace("__LANG__", "en" if en else "ar").replace("__DIR__", "ltr" if en else "rtl")
            .replace("__TITLE__", "Smart Home" if en else "البيت الذكي")
            .replace("__LEAD__", "Enter your password to control the strips." if en else "اكتب كلمة السر علشان تتحكم في المشتركات.")
            .replace("__PH__", "Password" if en else "كلمة السر")
            .replace("__BTN__", "Sign in" if en else "دخول"))


def finish_migration():
    if CFG.pop("_migrate", None):
        with LOCK:
            save_cfg()
        try:
            os.replace(CONFIG_PATH, CONFIG_PATH + ".bak")
        except OSError:
            pass
        log("imported settings from mttl_config.json into mttl.db (old file kept as .bak)")


def main():
    finish_migration()
    try:
        dev = ThreadedTCP(("0.0.0.0", DEVICE_PORT), DeviceHandler)
    except OSError as e:
        print("\n[!] Port %d is busy - the app is probably already running in another window." % DEVICE_PORT)
        print("    Close the other window and try again. (%s)" % e)
        input("Press Enter to exit...")
        return
    threading.Thread(target=dev.serve_forever, daemon=True).start()
    threading.Thread(target=poll_loop, daemon=True).start()
    threading.Thread(target=scheduler_loop, daemon=True).start()
    try:
        web = ThreadingHTTPServer(("0.0.0.0", WEB_PORT), Web)
    except OSError as e:
        print("\n[!] Port %d is busy: %s" % (WEB_PORT, e))
        input("Press Enter to exit...")
        return
    url = "http://127.0.0.1:%d" % WEB_PORT
    ip = current_ip()
    print("=" * 58)
    print("  MTTL-W01 Smart Strip - local controller")
    print("  Control page : %s" % url)
    if ip:
        print("  From phone   : http://%s:%d  (same Wi-Fi)" % (ip, WEB_PORT))
    print("  Strip port   : TCP %d   |  this PC IP: %s" % (DEVICE_PORT, ip or "?"))
    print("  Keep this window open. Close it to stop.")
    print("=" * 58)
    if "--no-browser" not in sys.argv:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        web.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
