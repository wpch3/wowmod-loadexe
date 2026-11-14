@echo off
rem ===========================================================================
rem  Download the public listfile (once)
rem
rem  What this does:
rem    tools\build-mod-mappings.py needs a "path -> FileDataID" table to turn
rem    your .blp/.m2 files into ids the client understands.
rem    That table comes from the public repo wowdev/wow-listfile (parts\*.csv).
rem
rem  Why it is a separate step:
rem    The full table is about 147 MB and 2.27 million lines. Shipping it in
rem    the package would make every download slow, and it changes over time.
rem
rem  Network: needs github.com. Run once, then it stays available.
rem  Use /auto to run without any pause (called by wowmod-mod.cmd).
rem ===========================================================================
setlocal EnableExtensions
chcp 65001 >nul 2>&1
cd /d "%~dp0"

rem /auto: wowmod-mod.cmd pause
set "WM_AUTO="
if /i "%~1"=="/auto" set "WM_AUTO=1"

set "WM_OUT=%~dp0..\.lf\wow-listfile.csv"
set "WM_DIR=%~dp0..\.lf"
set "WM_TMP=%TEMP%\wowmod-lf"

echo.
echo   [1/3] checking git ...
where git >nul 2>&1
if errorlevel 1 goto nogit

if exist "%WM_OUT%" (
  echo         already present: %WM_OUT%
  goto report
)

echo   [2/3] fetching listfile ...
if not exist "%WM_DIR%" mkdir "%WM_DIR%"
if exist "%WM_TMP%" rmdir /s /q "%WM_TMP%"

git clone --depth 1 --filter=blob:none --sparse https://github.com/wowdev/wow-listfile "%WM_TMP%"
if errorlevel 1 goto clipfail

pushd "%WM_TMP%"
rem sparse-checkout set
git sparse-checkout set --no-cone "/parts/*.csv"
if errorlevel 1 goto sparsefail
popd

echo         merging parts\*.csv ...
powershell.exe -NoLogo -NoProfile -Command ^
  "$d='%WM_TMP%\parts';" ^
  "$o='%WM_OUT%';" ^
  "$fs=Get-ChildItem -LiteralPath $d -Filter *.csv;" ^
  "if($fs.Count -eq 0){ Write-Host '        [FAIL] no csv found'; exit 1 };" ^
  "$fs | ForEach-Object { Get-Content -LiteralPath $_.FullName -Encoding UTF8 } | Set-Content -LiteralPath $o -Encoding UTF8;" ^
  "$n=(Get-Content -LiteralPath $o -Encoding UTF8).Count;" ^
  "Write-Host ('        merged ' + $fs.Count + ' files, ' + $n + ' lines')"
if errorlevel 1 goto mergefail

rmdir /s /q "%WM_TMP%" 2>nul

:report
echo.
echo   [3/3] done
echo.
for %%F in ("%WM_OUT%") do echo   %%~zF bytes: %WM_OUT%
echo.
echo   Next: run wowmod-mod.cmd (it uses this file automatically).
echo.
if not defined WM_AUTO pause
endlocal
exit /b 0

:nogit
echo   [FAIL] git not found.
echo          Either install Git for Windows, or download the listfile manually:
echo          https://github.com/wowdev/wow-listfile  (parts\*.csv)
echo          and concatenate them into:
echo            %WM_OUT%
echo.
if not defined WM_AUTO pause
endlocal
exit /b 1

:clipfail
echo   [FAIL] git clone failed. Check your network / proxy.
echo          Target: https://github.com/wowdev/wow-listfile
echo.
if not defined WM_AUTO pause
endlocal
exit /b 1

:sparsefail
popd 2>nul
echo   [FAIL] sparse-checkout failed.
echo.
if not defined WM_AUTO pause
endlocal
exit /b 1

:mergefail
echo   [FAIL] merging parts\*.csv failed.
echo.
if not defined WM_AUTO pause
endlocal
exit /b 1
