@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"

rem ===========================================================================
rem  wowmod scout - read-only reconnaissance
rem
rem  Writes NOT ONE BYTE to the client. It only reports facts:
rem    - real base address of the main module
rem    - how much of .text is decrypted right now
rem    - where each signature actually hits (and in which module)
rem    - the actual bytes currently at the two target RVAs
rem
rem  Why this exists: previous rounds kept GUESSING the base address and the
rem  hit location, and every wrong guess cost a round trip. This reports the
rem  facts so the next step does not need guessing.
rem
rem  Usage: double-click. Wait for the game window to show the login screen
rem  or the character, then send back wowmod\wowmod-scout.txt
rem ===========================================================================

set "WM_HOME=%~dp0"
if "!WM_HOME:~-1!"=="\" set "WM_HOME=!WM_HOME:~0,-1!"
set "WM_LOADER=%~dp0wowmod_loader.exe"
set "WM_GAME=%~1"

echo.
echo ==============================================================
echo   wowmod scout - read-only reconnaissance
echo ==============================================================
echo.

if not exist "%WM_LOADER%" (
  echo   [ERROR] wowmod_loader.exe not found next to this script.
  echo.
  pause
  exit /b 1
)

if not defined WM_GAME (
  for %%F in (
    "%WM_HOME%\WoW 12.0.7 - Firestorm.exe"
    "%WM_HOME%\Wow.exe"
    "%WM_HOME%\WowClassic.exe"
  ) do if exist "%%~F" if not defined WM_GAME set "WM_GAME=%%~F"
)

if not defined WM_GAME (
  echo   Drag the game exe onto this file, or pass its path.
  echo.
  pause
  exit /b 1
)

echo   client: %WM_GAME%
echo   dir   : %WM_HOME%
echo.
echo   This will launch the client and OBSERVE for 60 seconds.
echo   Nothing is modified. Close the game yourself when done.
echo.
pause

rem 60000 ms: long enough to reach the login screen / character select,
rem which is when the character texture code pages get decrypted.
"%WM_LOADER%" --mode scout --exe "%WM_GAME%" --workdir "%WM_HOME%" --wait 60000 --wait-exit

echo.
echo ==============================================================
echo   done
echo ==============================================================
echo.
if exist "%WM_HOME%\wowmod\wowmod-scout.txt" (
  echo   Report: %WM_HOME%\wowmod\wowmod-scout.txt
  echo.
  echo   Send that file back. It contains the real base address, the
  echo   decryption percentage, and where each signature actually hits.
) else (
  echo   [WARN] wowmod-scout.txt was not produced.
)
echo.
pause
exit /b 0
