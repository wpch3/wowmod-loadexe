@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"

rem ===========================================================================
rem  wowmod LOADER - install the mod loader (BOTH halves)
rem
rem  This is the real thing. Arctium's custom-file mechanism needs two halves
rem  and they only work together:
rem
rem    half 1  NoJump        - turn the "load from CASC" je into a no-op
rem    half 2  FileDataID    - install a lookup stub id -> local path
rem            -> mappings
rem
rem  Half 1 alone: client thinks "not in CASC, not local either" -> file errors.
rem  Half 2 alone: client never consults the table at all.
rem
rem  Usage: double-click. It waits for the client code to decrypt, then
rem  installs both halves into the running process. Nothing on disk changes.
rem ===========================================================================

set "WM_HOME=%~dp0"
if "!WM_HOME:~-1!"=="\" set "WM_HOME=!WM_HOME:~0,-1!"
set "WM_WOWMOD=%WM_HOME%\wowmod"
set "WM_LOADER=%~dp0wowmod_loader.exe"
set "WM_GAME=%~1"

echo.
echo ==============================================================
echo   wowmod LOADER  -  install mod loader (both halves)
echo ==============================================================
echo.

if not exist "%WM_LOADER%" (
  echo   [ERROR] wowmod_loader.exe not found next to this script.
  echo.
  pause
  exit /b 1
)

rem ---- data check first: no point patching without files ----
set "WM_MAPN=0"
set "WM_FILEN=0"
if exist "%WM_WOWMOD%\mappings" for %%M in ("%WM_WOWMOD%\mappings\*.txt") do set /a WM_MAPN+=1
if exist "%WM_WOWMOD%\files" for /f %%C in ('dir /b /s /a-d "%WM_WOWMOD%\files" 2^>nul ^| find /c /v ""') do set "WM_FILEN=%%C"

echo   mappings: %WM_WOWMOD%\mappings\*.txt   (%WM_MAPN% file^)
echo   files   : %WM_WOWMOD%\files\           (%WM_FILEN% files^)
echo.

if "%WM_MAPN%"=="0" goto nodata
if "%WM_FILEN%"=="0" goto nodata

if not defined WM_GAME (
  for %%F in (
    "%WM_HOME%\WoW 12.0.7 - Firestorm.exe"
    "%WM_HOME%\Wow.exe"
    "%WM_HOME%\WowClassic.exe"
  ) do if exist "%%~F" if not defined WM_GAME set "WM_GAME=%%~F"
)

if not defined WM_GAME (
  echo   [ERROR] Game exe not found. Drag the exe onto this file.
  echo.
  pause
  exit /b 1
)

echo   client: %WM_GAME%
echo.
echo   What will happen:
echo     1. launch the client suspended, then resume it
echo     2. wait until enough of .text is decrypted (lazy page decryption)
echo     3. install the FileDataID lookup stub   (half 2)
echo     4. apply the two NoJump branch patches  (half 1)
echo     5. leave the game running for you to look at the character
echo.
echo   Nothing is written to disk. Closing the game undoes everything.
echo.
pause

rem 240000 ms: the client only decrypts pages it actually executes, so we must
rem allow time to reach the world. Do not shorten this.
"%WM_LOADER%" --mode mods --exe "%WM_GAME%" --workdir "%WM_HOME%" --wait 240000 --wait-exit

echo.
echo ==============================================================
echo   done
echo ==============================================================
echo.
if exist "%WM_WOWMOD%\wowmod-mods.txt" (
  echo   Report: %WM_WOWMOD%\wowmod-mods.txt
) else (
  echo   [WARN] wowmod-mods.txt was not produced.
)
echo.
pause
exit /b 0

:nodata
echo   [STOP] The data side is empty, so patching would be pointless.
echo.
echo   The loader needs these two things prepared first:
echo     %WM_WOWMOD%\mappings\*.txt
echo     %WM_WOWMOD%\files\
echo.
echo   Run wowmod-mod.cmd once to build them from your mod folder,
echo   then come back and run this script.
echo.
pause
exit /b 5
