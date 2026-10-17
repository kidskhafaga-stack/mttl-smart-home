@echo off
title MTTL Smart Strip
cd /d "%~dp0"
chcp 65001 >nul

rem ---- find Python ----
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (where python >nul 2>nul && set "PY=python")
if not defined PY (
  echo.
  echo  [!] Python is not installed.
  echo      Install it from https://www.python.org/downloads/
  echo      and tick "Add python.exe to PATH" during setup, then run this file again.
  echo.
  pause
  exit /b 1
)

rem ---- open Windows Firewall for the strip (10086) and phone access (8080), once ----
netsh advfirewall firewall show rule name="MTTL Strip 10086" >nul 2>nul
if errorlevel 1 (
  echo  Asking Windows for permission to open ports 10086 and 8080 ^(one time only^)...
  powershell -NoProfile -Command "Start-Process cmd -Verb RunAs -Wait -ArgumentList '/c netsh advfirewall firewall add rule name=\"MTTL Strip 10086\" dir=in action=allow protocol=TCP localport=10086 profile=any & netsh advfirewall firewall add rule name=\"MTTL Strip Web 8080\" dir=in action=allow protocol=TCP localport=8080 profile=any'"
)

set PYTHONIOENCODING=utf-8
%PY% -u mttl_app.py
pause
