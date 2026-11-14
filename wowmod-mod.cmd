@echo off
rem ===========================================================================
rem  wowmod 一键准备模组数据
rem
rem  这一步做什么：
rem    把你的【完整模组目录】（例如 _midnight_\Character 那棵 21 个种族的树）
rem    变成 Arctium 机制要求的两个东西：
rem      wowmod\mappings\mod.txt    每行 "FileDataID;Character/BloodElf/Female/xxx.blp"
rem      wowmod\files\              实际文件，保持同样相对路径
rem
rem  为什么要这一步：
rem    客户端只认 FileDataID，不认文件名。它拿到一个 id，去查表，
rem    表里没有就当成"CASC 里没这个资源"。所以必须先把路径换算成 id。
rem    手工查两百多个文件不现实，这里全自动。
rem
rem  安全性：
rem    只读取你的模组目录，不修改/不移动/不删除任何东西。
rem    files\ 里默认用【硬链接】而不是复制 —— 同一份贴图不占两份空间。
rem
rem  用法：双击。第一次会让你选模组目录（或把目录拖到本文件上）。
rem ===========================================================================
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"

set "WM_DIR=%~dp0"
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

rem 先猜：游戏目录下的 Character 就是完整模组最常见的形态
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
python "%WM_DIR%tools\build-mod-mappings.py" --mod "!WM_MOD!" --listfile "%WM_LF%" --out "%WM_DIR%"
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
