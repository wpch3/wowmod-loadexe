@echo off
rem ===========================================================================
rem  wowmod - one click, self contained.
rem
rem  This is the 'single exe' entry point. It does NOT need python and does NOT
rem  need a pre-generated wowmod\mappings + wowmod\files folder: the loader
rem  itself scans your mod folder and resolves every file to its FileDataID
rem  using the listfile.
rem
rem  Everything Arctium does is done here, in one pass:
rem    1. anti-crash      - integrity checks -> ret 0, remap jumps shifted
rem    2. NoJump          - both CASC load branches disabled
rem    3. FileDataID hook - lookup stub returns the absolute path of your file
rem
rem  Usage: double-click, or drag your mod folder onto this file.
rem ===========================================================================
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"

rem %~dp0 ends with a backslash; passing it through would escape the closing
rem quote and produce WinError 123. Keep a backslash-free copy.
set "WM_HOME=%~dp0"
if "!WM_HOME:~-1!"=="\" set "WM_HOME=!WM_HOME:~0,-1!"
set "WM_LOADER=!WM_HOME!\wowmod_loader.exe"

echo.
echo ==============================================================
echo   wowmod  one click  (self contained)
echo ==============================================================
echo.

if not exist "!WM_LOADER!" (
  echo   [FAIL] wowmod_loader.exe not found next to this file.
  echo.
  pause
  exit /b 1
)

rem ---------------------------------------------- 1. find the client
set "WM_GAME="
if defined WM_EXE set "WM_GAME=%WM_EXE%"
if not defined WM_GAME (
  for %%F in (
    "!WM_HOME!\WoW 12.0.7 - Firestorm.exe"
    "!WM_HOME!\Wow.exe"
    "!WM_HOME!\WowClassic.exe"
    "!WM_HOME!\_retail_\Wow.exe"
  ) do if exist "%%~F" if not defined WM_GAME set "WM_GAME=%%~F"
)
if not defined WM_GAME (
  echo   [1/4] pick your client exe ...
  for /f "usebackq delims=" %%L in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms^|Out-Null; $d=New-Object System.Windows.Forms.OpenFileDialog; $d.Filter='Client exe^|*.exe'; $d.Title='Select Wow.exe / WoW 12.0.7 - Firestorm.exe'; if($d.ShowDialog() -eq 'OK'){Write-Output $d.FileName}" 2^>nul`) do set "WM_GAME=%%L"
)
if not defined WM_GAME (
  echo   [FAIL] no client exe selected.
  pause
  exit /b 1
)
echo   client: !WM_GAME!

rem ---------------------------------------------- 2. find the mod folder
set "WM_MODS="
if not "%~1"=="" if exist "%~1\" set "WM_MODS=%~1"
if not defined WM_MODS (
  for %%D in (
    "D:\Midnight Open Beta\_midnight_"
    "!WM_HOME!\_midnight_"
  ) do if exist "%%~D\wowmod" if not defined WM_MODS set "WM_MODS=%%~D"
)
if not defined WM_MODS (
  echo   [2/4] pick your mod folder ...
  for /f "usebackq delims=" %%L in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms^|Out-Null; $d=New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description='Select your mod folder (the one containing Character\ or item\ or Creature\)'; if($d.ShowDialog() -eq 'OK'){Write-Output $d.SelectedPath}" 2^>nul`) do set "WM_MODS=%%L"
)
if not defined WM_MODS (
  echo   [FAIL] no mod folder selected.
  pause
  exit /b 1
)
echo   mods  : !WM_MODS!

rem ---------------------------------------------- 3. find the listfile
set "WM_LF="
for %%D in (
  "!WM_HOME!\.lf\wow-listfile.csv"
  "!WM_HOME!\listfile.csv"
  "!WM_MODS!\.lf\wow-listfile.csv"
  "!WM_MODS!\listfile.csv"
) do if exist "%%~D" if not defined WM_LF set "WM_LF=%%~D"

if not defined WM_LF (
  echo   [3/4] listfile not found, downloading once ...
  if exist "!WM_HOME!\tools\fetch-listfile.cmd" (
    call "!WM_HOME!\tools\fetch-listfile.cmd" /auto
  )
  for %%D in (
    "!WM_HOME!\.lf\wow-listfile.csv"
    "!WM_HOME!\listfile.csv"
  ) do if exist "%%~D" if not defined WM_LF set "WM_LF=%%~D"
)
if not defined WM_LF (
  echo   [FAIL] no listfile. FileDataID can only be resolved from it.
  echo          Put wow-listfile.csv next to this file, or run tools\fetch-listfile.cmd
  pause
  exit /b 1
)
echo   listfile: !WM_LF!

rem ---------------------------------------------- 4. install
echo   [4/4] starting client and installing ...
echo.
rem 900000 ms is only an upper bound: the loader stops the moment the target
rem signature is found. It never asks you to log in or advance the client.
"!WM_LOADER!" --mode mods --exe "!WM_GAME!" --workdir "!WM_HOME!" ^
    --mods "!WM_MODS!" --listfile "!WM_LF!" --wait 900000 --wait-exit
set "WM_RC=!errorlevel!"

echo.
echo ==============================================================
if exist "!WM_HOME!\wowmod\wowmod-mods.txt" (
  echo   Report: !WM_HOME!\wowmod\wowmod-mods.txt
)
if not "!WM_RC!"=="0" (
  echo   [exit !WM_RC!] see the messages above.
)
echo ==============================================================
echo.
pause
endlocal
exit /b !WM_RC!
