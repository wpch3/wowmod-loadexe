@echo off
rem ===========================================================================
rem  下载公开 listfile（一次就好）
rem
rem  这是做什么的：
rem    tools\build-mod-mappings.py 需要一张「路径 -> FileDataID」对照表，
rem    才能把你模组里的 .blp/.m2 换算成游戏认识的 id。
rem    那张表来自公开仓库 wowdev/wow-listfile 的 parts\*.csv。
rem
rem  为什么要单独下：
rem    你模组里的路径很多，完整对照表约 147 MB/227 万条。
rem    把它塞进发布包不合适（下载慢/还经常变），所以做成按需拉取。
rem
rem  网络要求：能访问 github.com。只需要跑一次，之后一直可用。
rem ===========================================================================
setlocal EnableExtensions
chcp 65001 >nul 2>&1
cd /d "%~dp0"

rem /auto: 由 wowmod-mod.cmd 调用时静默运行，不 pause、不等待。
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
rem 注意：sparse-checkout set 是【破坏性】的，必须一次把所有路径列全。
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
