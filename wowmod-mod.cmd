@echo off
rem ===========================================================================
rem  wowmod - prepare mod data (one click)
rem
rem  What this does:
rem    Turn a full mod folder (e.g. _midnight_\Character with 21 races)
rem    into the two things the Arctium mechanism needs:
rem      wowmod\mappings\mod.txt    one line per file: <FileDataID>;<game path>
rem      wowmod\files\              the actual files, same relative layout
rem
rem  Why this is required:
rem    The client only knows FileDataID. It never scans your folder tree.
rem    A loose .blp sitting in the game root is invisible to it.
rem    So every path must first be translated into a FileDataID.
rem
rem  Safety:
rem    Read-only with respect to your mod folder. Nothing is moved or deleted.
rem    files\ uses hard links by default, so a 12MB texture is not stored twice.
rem
rem  Usage: double-click, then pick your mod folder. You can also drag a
rem         folder onto this file.
rem ===========================================================================
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"

rem %~dp0 always ends with a backslash. Passing that straight into a
rem command line means the final backslash escapes the closing quote, and the
rem argument arrives as  ..._midnight_"   <- literally a quote character.
rem That is what produced WinError 123. So keep a backslash-free copy.
set "WM_DIR=%~dp0"
set "WM_HOME=%~dp0"
rem Use delayed expansion for the trailing-backslash test: with %VAR% the
rem closing quote after a backslash gets escaped and cmd reports a syntax error.
if "!WM_HOME:~-1!"=="\" set "WM_HOME=!WM_HOME:~0,-1!"
set "WM_LF=%WM_DIR%.lf\wow-listfile.csv"
set "WM_MOD=%~1"

echo.
echo ==============================================================
echo   wowmod 一键准备模组数据
echo ==============================================================
echo.

echo   [1/4] checking listfile ...
if not exist "%WM_LF%" (
  echo         not found, downloading once ...
  echo.
  call "%WM_DIR%tools\fetch-listfile.cmd" /auto
  if not exist "%WM_LF%" (
    echo.
    echo   [FAIL] listfile still missing: %WM_LF%
    echo          Run tools\fetch-listfile.cmd manually, then retry.
    echo.
    pause
    exit /b 1
  )
)
echo         ok: %WM_LF%
echo.

rem ------------------------------------------------ 2. 找模组目录
if defined WM_MOD if exist "%WM_MOD%\" goto gotmod
if defined WM_MOD if exist "%WM_MOD%" (
  for %%F in ("%WM_MOD%") do set "WM_MOD=%%~dpF"
  goto gotmod
)
set "WM_MOD="

rem Character
for %%D in (
  "D:\Midnight Open Beta\_midnight_\Character"
  "D:\Midnight Open Beta\Character"
) do (
  if not defined WM_MOD if exist "%%~D\" set "WM_MOD=%%~D"
)

if not defined WM_MOD (
  echo   [2/4] pick your mod folder ^(the one containing Character\ or similar^)
  echo.
  for /f "usebackq delims=" %%L in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms|Out-Null; $d=New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description='Select your mod folder (e.g. _midnight_\Character)'; if($d.ShowDialog() -eq 'OK'){Write-Output $d.SelectedPath}" 2^>nul`) do set "WM_MOD=%%L"
)
if not defined WM_MOD goto cancelled

:gotmod
set "WM_MOD=!WM_MOD:"=!"
if not exist "!WM_MOD!\" (
  echo   [FAIL] not a directory: !WM_MOD!
  pause
  exit /b 1
)
echo   [2/4] mod folder: !WM_MOD!
echo.

rem ------------------------------------------------ 3. 扫描 + 生成
echo   [3/4] scanning and building mappings ...
echo.
python "%WM_DIR%tools\build-mod-mappings.py" --mod "!WM_MOD!" --listfile "%WM_LF%" --out "%WM_HOME%"
set "WM_RC=!errorlevel!"
echo.

if not "!WM_RC!"=="0" (
  echo   [FAIL] mapping generation failed ^(code !WM_RC!^).
  echo          Read the messages above.
  echo.
  pause
  exit /b 1
)

rem ------------------------------------------------ 4. 校验产物
echo   [4/4] verifying output ...
set "WM_MAP=%WM_DIR%mappings\mod.txt"
if not exist "%WM_MAP%" (
  echo   [FAIL] mapping file not created: %WM_MAP%
  pause
  exit /b 1
)
powershell.exe -NoLogo -NoProfile -Command ^
  "$m='%WM_MAP%';" ^
  "$n=@(Get-Content -LiteralPath $m -Encoding UTF8 | Where-Object { $_ -match '^\d+;' }).Count;" ^
  "$f=(Get-ChildItem -LiteralPath '%WM_DIR%files' -Recurse -File -ErrorAction SilentlyContinue).Count;" ^
  "Write-Host ('        mappings: ' + $n + ' entries');" ^
  "Write-Host ('        files   : ' + $f + ' files');" ^
  "if($n -eq 0){ Write-Host '        [FAIL] no mappings written' }" ^
  "else { Write-Host ''; Write-Host '        Ready. Now run wowmod-patch.cmd' }"

echo.
echo   mappings: %WM_MAP%
echo   files   : %WM_DIR%files\
echo.
pause
endlocal
exit /b 0

:cancelled
echo   cancelled.
echo.
pause
exit /b 1
