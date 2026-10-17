# البيت الذكي — Smart Home for MTTL-W01 strips

Local control for the Korean **LG U+ / TONLY MTTL-W01** 4-outlet smart power strip (the "مشترك الكوري"), without the Korean cloud, an internet connection, or a subscription.

تحكم محلي في المشترك الكوري MTTL-W01 من غير سيرفرات كورية ولا إنترنت ولا اشتراك.

## Features · المميزات

- Several strips, each outlet controlled on its own; whole room / whole home on-off
- Name each outlet, set the appliance type and room
- Timers (on for / off after / on after) and schedules (repeat days or one-time, optional auto-off)
- Charger mode: switch off automatically when a phone or laptop finishes charging
- Energy dashboard: day (hourly), week, month, year or any date range; comparison with the previous period; breakdown by appliance or room; cost in EGP; Excel export
- LG TVs (webOS), all local: full remote (arrows/OK, back, home, settings, number pad, colour keys, media keys; keyboard shortcuts on a computer), launch any installed app with its real icon, volume slider, inputs, type text into the TV, screen off with sound on, power on via Wake-on-LAN
- LG ThinQ appliances through LG's official ThinQ Connect API: air-conditioner thermostat with modes, fan speed and off-timer; washer/dryer progress and a log entry when a cycle finishes; fridge and freezer temperatures; every other setting the device exposes
- Guided Wi-Fi setup for new strips, network diagnostics, optional password
- **Strip messages** view on each strip: the live raw protocol log, with a check for any data beyond the 4 outlets (e.g. a USB channel), shown on the strip if found
- Arabic and English interface
- SQLite storage (`mttl.db`)

## Run · التشغيل (Windows)

1. Install Python 3.8+ from python.org and tick **Add python.exe to PATH**.
2. Double-click `Start-Strip.bat`. The first run asks for admin permission once, to open TCP port 10086 in Windows Firewall.
3. The control page opens at `http://127.0.0.1:8080`. Keep the black window open — schedules and timers run while the app runs.

On other systems: `python3 mttl_app.py`.

## Add a strip · إضافة مشترك

Once per strip. With this computer on your home Wi-Fi (2.4 GHz):

1. Hold the strip's main power button for 10 seconds until the light blinks fast.
2. Open **Add strip**, enter your Wi-Fi password and press **Start setup**.

The strip stores your Wi-Fi and this computer's IP address and connects by itself from then on. Reserve this computer's IP in your router (DHCP reservation) so it never changes.

## LG devices · أجهزة LG

Open **Settings → Connect LG devices**.

- **TV (webOS):** with the TV on, press **Find TV** (or type its IP) and **Pair**, then accept the request on the TV with the remote. To turn it on from off, enable *Turn on via Wi-Fi / LAN* on the TV; the app sends Wake-on-LAN to the TV's MAC address.
- **ThinQ appliances:** create a Personal Access Token at [connect-pat.lgthinq.com](https://connect-pat.lgthinq.com) (sign in with your ThinQ account → *ADD NEW TOKEN* → tick all permissions → *CREATE TOKEN*), paste it with your country code (e.g. `EG`) and press **Connect**. Devices must already be added in the LG ThinQ app. Controls are built from each device's own profile, so any ThinQ device type works.

TV control follows the protocol used by [aiowebostv](https://github.com/home-assistant-libs/aiowebostv); ThinQ calls follow LG's official [pythinqconnect](https://github.com/thinq-connect/pythinqconnect).

## How it works · طريقة العمل

| Step | Direction | Message |
|---|---|---|
| Setup | app → strip `192.168.1.1:30300` | `up:ip:<pc ip>` → `up:connect:<ssid>:<pass>` → `up:reboot:0` |
| Runtime | strip → app TCP `10086` | `up:bootinfo:…`, `up:getinfo:…` telemetry |
| Control | app → strip | `up:onoff:<1-4>:<on\|off>`, `up:getinfo:all` |

Protocol details come from community reverse-engineering work:
[AmrEmad0/MTTL-W01_APP](https://github.com/AmrEmad0/MTTL-W01_APP) and
[HanyArnous/power_strip](https://github.com/HanyArnous/power_strip).

## Files

| File | Purpose |
|---|---|
| `mttl_app.py` | The whole app: device server, scheduler, web UI (Python standard library only) |
| `Start-Strip.bat` | Windows launcher: finds Python, opens the firewall port, starts the app |
| `mttl.db` | Created on first run — strips, outlets, schedules, energy history, LG tokens (not committed) |

## Notes

- The strip only supports 2.4 GHz Wi-Fi, and the Wi-Fi name/password can't contain `:`.
- Forgot the password? Close the app and delete the `auth` row from the `settings` table in `mttl.db`.
- The strip protocol is plain TCP with no authentication. Keep port 10086 on your local network only.
