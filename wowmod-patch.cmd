@echo off
rem ===========================================================================
rem  wowmod 一键打补丁（Arctium 机制）
rem
rem  这一步做什么：
rem    把客户端里「按 FileDataID 从 CASC 加载」和「按路径从 CASC 加载」这两条
rem    条件跳转（je）改成【永不跳】。于是客户端以为 CASC 里没有这个资源，
rem    回头去查 mappings\*.txt 里登记的本地文件 —— 这就是 Arctium 让模组生效的原理。
rem
rem  为什么不是上次那个「探针」：
rem    上次是在查找函数入口装跳板（要搬指令/写引擎/改控制流）；
rem    这次只改 4 个字节的条件跳转，不加 hook/不写跳板/不碰函数入口。
rem    前几次崩溃的根因（往不可执行页写代码）在这里根本不存在。
rem
rem  安全性：
rem    只改内存，不动磁盘上任何文件，客户端退出即消失。
rem    每条补丁都要求：全映像唯一命中 + 补丁点确实是 0F 84 + 写前复读一致。
rem    任一条不满足就跳过并写进报告，绝不猜着打。
rem
rem  用法：双击本文件。先在 wowmod\ 里放好 mappings 和 files，再跑。
rem ===========================================================================
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"

set "WM_WAIT_MS=120000"
set "WM_LOADER=%~dp0wowmod_loader.exe"
set "WM_RT=%~dp0wowmod_rt.dll"
set "WM_GAME=%~1"

powershell.exe -NoLogo -NoProfile -Command "Write-Host ''; Write-Host '=============================================================='; Write-Host '  wowmod 一键旁路记录 - FileDataID 探针'; Write-Host '=============================================================='; Write-Host ''"

if not exist "%WM_LOADER%" goto nofiles
if not exist "%WM_RT%" goto nofiles

rem ------------------------------------------------- 0. 客户端不能在跑
tasklist /nh 2>nul | findstr /i "wow" | findstr /v /i "wowmod" >nul
if not errorlevel 1 (
  powershell.exe -NoLogo -NoProfile -Command "Write-Host '  [提示] 检测到 WoW 客户端正在运行。'; Write-Host '         请先退出游戏，再按任意键继续。'; Write-Host ''"
  pause
)

rem ------------------------------------------------- 1. 找 exe
if defined WM_GAME if exist "%WM_GAME%" goto gotexe
set "WM_GAME="
for %%D in (
  "D:\Midnight Open Beta\_midnight_"
  "D:\Midnight Open Beta"
  "C:\Program Files (x86)\World of Warcraft\_retail_"
  "D:\World of Warcraft\_retail_"
  "C:\World of Warcraft\_retail_"
) do (
  if exist "%%~D" (
    for /f "delims=" %%N in ('dir /b /a-d "%%~D\Wow*.exe" "%%~D\*Firestorm*.exe" 2^>nul') do (
      if not defined WM_GAME if /i not "%%~nN"=="wowmod_loader" set "WM_GAME=%%~D\%%N"
    )
  )
)
if defined WM_GAME if exist "%WM_GAME%" goto gotexe

for /f "usebackq delims=" %%L in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms|Out-Null; $d=New-Object System.Windows.Forms.OpenFileDialog; $d.Title='选择 WoW 客户端 exe'; $d.Filter='WoW (*.exe)|*.exe'; if($d.ShowDialog() -eq 'OK'){Write-Output $d.FileName}" 2^>nul ^| findstr /r ".exe$"`) do set "WM_GAME=%%L"
if not defined WM_GAME (
  echo   [提示] 弹窗不可用。请粘贴客户端 exe 的完整路径后回车：
  set /p "WM_GAME=  路径: "
)
if not defined WM_GAME goto cancelled
set "WM_GAME=!WM_GAME:"=!"
if not exist "!WM_GAME!" goto cancelled

:gotexe
for %%F in ("%WM_GAME%") do set "WM_GAMEDIR=%%~dpF"
echo   客户端: %WM_GAME%
echo   目录  : %WM_GAMEDIR%
echo.

echo   [1/4] checking version ...
for /f "delims=" %%V in ('"%WM_LOADER%" --version 2^>nul') do echo         %%V
echo.

powershell.exe -NoLogo -NoProfile -Command ^
  "Write-Host '==============================================================';" ^
  "Write-Host '==============================================================';" ^
  "Write-Host '  接下来会：';" ^
  "Write-Host '    1，定位两条「从 CASC 加载」的条件跳转（要等代码解密完）';" ^
  "Write-Host '    2，校验：全映像唯一命中 + 补丁点确实是 je + 写前复读一致';" ^
  "Write-Host '    3，把那 4 个字节改成 00 00 00 00';" ^
  "Write-Host '    4，启动游戏，你自己进世界看角色模型';" ^
  "Write-Host '';" ^
  "Write-Host '  前提：wowmod\\mappings\\*.txt + wowmod\\files\\ 已经放好要替换的文件。';" ^
  "Write-Host '';" ^
  "Write-Host '  补丁只改内存，关掉游戏就没了（不会弄坏客户端）。';" ^
  "Write-Host '  报告会写到 wowmod\\wowmod-patch.txt。';" ^
  "Write-Host '==============================================================';" ^
  "Write-Host ''"
pause

rem ------------------------------------------------- 2. 跑
echo   [2/4] launching client and applying branch patches ...
echo.
"%WM_LOADER%" --exe "%WM_GAME%" --mode patch --apply --wait %WM_WAIT_MS%
set "WM_RC=!errorlevel!"
echo.

set "WM_OUT=%WM_GAMEDIR%wowmod\wowmod-patch.txt"
if not exist "%WM_OUT%" (
  powershell.exe -NoLogo -NoProfile -Command "Write-Host '  [FAIL] no report file:'; Write-Host '         %WM_OUT%'; Write-Host ''; Write-Host '  Send the console output above back.'"
  pause
  exit /b 1
)

echo   [3/4] summarizing ...
echo.
powershell.exe -NoLogo -NoProfile -Command ^
  "$p='%WM_OUT%';" ^
  "$t=Get-Content -LiteralPath $p -Encoding UTF8;" ^
  "$ok=@($t | Select-String -Pattern '\[PATCHED\]').Count;" ^
  "$sk=@($t | Select-String -Pattern '\[SKIPPED\]').Count;" ^
  "Write-Host ('        patched: ' + $ok + '   skipped: ' + $sk);" ^
  "if($ok -gt 0){ Write-Host '        patched and active. Enter the world and look at the model.' }" ^
  "else { Write-Host '        nothing patched. Send the report back.' }"

echo.
echo   [4/4] done
echo.
echo   report: %WM_OUT%
echo.
echo   Send back wowmod-patch.txt (shows which branch was patched).
echo.
pause
endlocal
exit /b 0

:nofiles
echo   [失败] 本文件必须和 wowmod_loader.exe / wowmod_rt.dll 放在同一目录。
echo   请先完整解压 wowmod-oneclick.zip。
echo.
pause
exit /b 1

:cancelled
echo   已取消。
echo.
pause
exit /b 1
