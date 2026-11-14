@echo off
rem ===========================================================================
rem  wowmod 一键旁路记录（FileDataID 探针）
rem
rem  这一步做什么：
rem    在客户端的 FileDataID 查找函数（RVA 0x33e06a0，CAS.cpp，
rem    Arctium 的 CustomFileIdHook 目标）上装一个「只记录」的跳板。
rem
rem  安全性：
rem    只记录传入的 id，然后原样执行被搬走的指令并跳回。
rem    不改变返回值，不改变控制流，不改变任何寄存器结果。
rem    退出时会把原始字节写回。最坏情况是日志不准，不会影响客户端加载资源。
rem
rem  用法：双击本文件，照提示在游戏里正常玩一会儿。
rem ===========================================================================
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"

set "WM_WAIT_MS=300000"
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
  "Write-Host '  接下来启动游戏并装探针。装好后请在游戏里做这些事：';" ^
  "Write-Host '    1，登录，在角色选择界面来回切几个角色（看模型预览）';" ^
  "Write-Host '    2，进入游戏世界';" ^
  "Write-Host '    3，打开角色面板 / 幻化 / 理发店';" ^
  "Write-Host '    4，进出一次场景或换个地图';" ^
  "Write-Host '';" ^
  "Write-Host '  这些操作会触发客户端加载角色模型，我们要的就是它加载时';" ^
  "Write-Host '  实际传进 FileDataID 查找函数的那些 id。';" ^
  "Write-Host '';" ^
  "Write-Host '  最长监控 5 分钟（' + 300000 + ' 毫秒），结束时会自动卸载探针。';" ^
  "Write-Host '  想提前结束：关掉这个窗口，然后重跑一次并让游戏重新启动即可。';" ^
  "Write-Host '==============================================================';" ^
  "Write-Host ''"
pause

rem ------------------------------------------------- 2. 跑
echo   [2/4] launching client and installing probe ...
echo.
"%WM_LOADER%" --exe "%WM_GAME%" --mode probe --wait %WM_WAIT_MS%
set "WM_RC=!errorlevel!"
echo.

set "WM_OUT=%WM_GAMEDIR%wowmod\wowmod-probe.txt"
if not exist "%WM_OUT%" (
  powershell.exe -NoLogo -NoProfile -Command "Write-Host '  [失败] 没有生成记录文件：'; Write-Host '         %WM_OUT%'; Write-Host ''; Write-Host '  请把上面的完整输出发回来（尤其是 [失败] 那几行）。'; Write-Host ''"
  pause
  exit /b 1
)

echo   [3/4] summarizing ...
echo.
powershell.exe -NoLogo -NoProfile -Command ^
  "$p='%WM_OUT%';" ^
  "$lines=Get-Content -LiteralPath $p -Encoding UTF8;" ^
  "$ids=@(); foreach($l in $lines){ if($l -match 'id=(\d+)'){ $ids += [int]$Matches[1] } };" ^
  "Write-Host ('        记录到 ' + $ids.Count + ' 次调用，' + ($ids | Sort-Object -Unique).Count + ' 个不同 id');" ^
  "if($ids.Count -gt 0){" ^
  "  Write-Host '';" ^
  "  Write-Host '  id 范围: ' -NoNewline;" ^
  "  Write-Host (($ids | Measure-Object -Minimum).Minimum.ToString() + ' ~ ' + ($ids | Measure-Object -Maximum).Maximum.ToString());" ^
  "}"

echo.
echo   [4/4] done
echo.
echo   记录文件: %WM_OUT%
echo.
echo   Send back wowmod-probe.txt (it lists the real FileDataID calls).
echo   Use wowmod-listid to look up which paths those ids map to.
echo.
pause
endlocal
exit /b 0

:nofiles
echo   [失败] 本文件必须和 wowmod_loader.exe，wowmod_rt.dll 放在同一目录。
echo   请先完整解压 wowmod-oneclick.zip。
echo.
pause
exit /b 1

:cancelled
echo   已取消。
echo.
pause
exit /b 1
