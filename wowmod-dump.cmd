@echo off
rem ===========================================================================
rem  wowmod 一键导出（WoW 12.0.7 明文主模块）
rem
rem  为什么需要这个：客户端 .text 是按 4KB 页【惰性解密】的，
rem  只有游戏真正执行到的代码页才是明文。所以必须【先进游戏玩一会儿】再抓，
rem  否则导出的 113MB 里九成还是密文（上一版只拿到 9.6%）。
rem
rem  用法：双击本文件，照屏幕提示操作，不需要输入任何命令。
rem  也可以把游戏 exe 直接拖到本文件图标上。
rem ===========================================================================
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"

set "WM_WAIT_MS=180000"
set "WM_LOADER=%~dp0wowmod_loader.exe"
set "WM_RT=%~dp0wowmod_rt.dll"
set "WM_GAME=%~1"

echo.
echo ==============================================================
echo   wowmod 一键导出 - WoW 12.0.7 明文主模块
echo ==============================================================
echo.

if not exist "%WM_LOADER%" goto nofiles
if not exist "%WM_RT%" goto nofiles

rem ------------------------------------------------- 0. 先确认客户端没在运行
rem 客户端已经在跑的话，再启一个会被它拉起来，拿到的可能不是新进程的主模块。
tasklist /nh 2>nul | findstr /i "wow" | findstr /v /i "wowmod" >nul
if not errorlevel 1 (
  echo   [提示] 检测到 WoW 客户端正在运行。
  echo          请先手动退出游戏，再回来按任意键继续。
  echo.
  pause
)

rem ------------------------------------------------- 1. 找游戏 exe
if defined WM_GAME if exist "%WM_GAME%" goto gotexe

rem 注意：cmd 的 for %%F in (通配符) 不会展开通配符，必须借 dir /b 取。
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

:pick
echo   没能自动找到游戏 exe，请在弹出的窗口里手动选择。
echo   （一般叫 "WoW 12.0.7 - Firestorm.exe"，在 _midnight_ 文件夹内）
echo.
for /f "usebackq delims=" %%L in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms|Out-Null; $d=New-Object System.Windows.Forms.OpenFileDialog; $d.Title='选择 WoW 客户端 exe'; $d.Filter='WoW (*.exe)|*.exe'; if($d.ShowDialog() -eq 'OK'){Write-Output $d.FileName}" 2^>nul ^| findstr /r ".exe$"`) do set "WM_GAME=%%L"
rem 上面依赖 System.Windows.Forms 自动加载；若弹窗没出来，退回手动输入。
if not defined WM_GAME (
  echo   [提示] 弹窗不可用。请把客户端 exe 的完整路径粘贴到这里，然后回车：
  set /p "WM_GAME=  路径: "
)
if not defined WM_GAME goto cancelled
rem 去掉用户可能带上的引号
set "WM_GAME=%WM_GAME:"=%"
if not exist "%WM_GAME%" goto cancelled

:gotexe
for %%F in ("%WM_GAME%") do set "WM_GAMEDIR=%%~dpF"
echo   客户端: %WM_GAME%
echo   目录  : %WM_GAMEDIR%
echo.

rem ------------------------------------------------- 2. 自检
echo   [1/4] 检查程序版本 ...
for /f "delims=" %%V in ('"%WM_LOADER%" --version 2^>nul') do echo         %%V
echo.

rem ------------------------------------------------- 3. 说清楚要做什么
rem 这段中文提示改用 PowerShell 输出。
rem 原因：cmd.exe 在 chcp 65001 下解析【较长的 UTF-8 echo 行】会错位
rem （实测：同一个块里第 2、4 行正常，最长的第 1、3 行被当成命令执行，
rem  报 "'回切几个角色…' is not recognized"）。换成 powershell 写，
rem 与代码页无关，彻底绕开这个问题。
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command ^
  "Write-Host '';" ^
  "Write-Host '==============================================================';" ^
  "Write-Host '  接下来会启动游戏，期间【不需要】任何额外操作。';" ^
  "Write-Host '';" ^
  "Write-Host '  请在游戏里做这些事（目的：让壳把相关代码页解密出来）：';" ^
  "Write-Host '    1、登录，在角色选择界面来回切几个角色看模型预览';" ^
  "Write-Host '    2、进入游戏世界';" ^
  "Write-Host '    3、打开角色面板 / 幻化 / 理发店（会加载角色模型）';" ^
  "Write-Host '    4、进出一次场景，或换个地图';" ^
  "Write-Host '';" ^
  "Write-Host ('  程序最多采样 3 分钟（' + %WM_WAIT_MS% + ' 毫秒），');" ^
  "Write-Host '  一旦进度【稳定不再上升】就自动导出，你不用回来点任何东西。';" ^
  "Write-Host '';" ^
  "Write-Host '  注：这一步只是读取内存，不改客户端一个字节，重跑无副作用。';" ^
  "Write-Host '==============================================================';"
pause

rem ------------------------------------------------- 4. 运行
echo   [2/4] 启动客户端并采样（要等，属正常）...
echo.
"%WM_LOADER%" --exe "%WM_GAME%" --mode sigscan --dump-module --wait %WM_WAIT_MS%
set "WM_RC=!errorlevel!"
echo.

set "WM_OUT=%WM_GAMEDIR%wowmod\dump\main-module.bin"
if not exist "%WM_OUT%" (
  echo   [失败] 没有生成导出文件：
  echo          %WM_OUT%
  echo.
  echo   可能原因：客户端没起来 / 路径含特殊字符 / 被杀软拦下。
  echo   请把上面的完整输出发回来。
  echo.
  pause
  exit /b 1
)

rem ------------------------------------------------- 5. 量化
echo   [3/4] 对照磁盘 exe 统计明文比例 ...
echo.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$dump='%WM_OUT%'; $exe='%WM_GAME%'; $dm=[IO.File]::OpenRead($dump); $de=[IO.File]::OpenRead($exe); try { $m=New-Object byte[] 4096; $d=New-Object byte[] 4096; $same=0; $diff=0; $off=0x400; $va=0x1000; $size=0x35a2000; $dm.Position=$va; for($i=0; $i -lt [math]::Floor($size/4096); $i++){ $de.Position=$off+$i*4096; if($de.Read($d,0,4096) -lt 4096){break}; if($dm.Read($m,0,4096) -lt 4096){break}; $eq=$true; for($k=0; $k -lt 4096; $k++){ if($m[$k] -ne $d[$k]){$eq=$false; break} }; if($eq){$same++} else {$diff++} }; $total=$same+$diff; if($total -le 0){ Write-Host '        [失败] 读不到 .text，请把输出发回来。'; return }; Write-Host ('        明文页(与磁盘不同) = ' + $diff + ' / ' + $total + ' = ' + [math]::Round(100.0*$diff/$total,1) + '%'); Write-Host ('        密文页(与磁盘相同) = ' + $same); if($diff -lt 3000){ Write-Host '        [偏低] 建议重跑，并在游戏里多待一会儿、多切几次角色。' } else { Write-Host '        [够用] 可以拿去做特征码匹配了。' } } finally { $dm.Dispose(); $de.Dispose() }"

echo.
echo   [4/4] 完成
echo.
echo   导出文件: %WM_OUT%
echo   分析报告: %WM_GAMEDIR%wowmod\wowmod-analysis.txt
echo.
echo   请把【上面的百分比】连同这两个文件发回来。
echo.
pause
endlocal
exit /b 0

:nofiles
echo   [失败] 本文件必须和 wowmod_loader.exe、wowmod_rt.dll 放在同一目录。
echo   请先完整解压 wowmod-oneclick.zip，再双击本文件。
echo.
pause
exit /b 1

:cancelled
echo   已取消（没有选择客户端 exe）。
echo.
pause
exit /b 1
