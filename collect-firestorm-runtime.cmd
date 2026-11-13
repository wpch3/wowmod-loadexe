@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\collect-firestorm-runtime.ps1"
echo.
echo When finished, attach firestorm-runtime-dumps.zip from this folder to the Arena chat.
pause
