@echo off
rem ============================================================
rem  wowmod 一键启动器  (WoW 12.0.7 松散文件加载)
rem
rem  用法 A（推荐）：把游戏 exe 直接拖到本文件图标上
rem  用法 B：双击本文件，按提示用数字选择
rem
rem  不需要手动输任何路径或命令。
rem ============================================================
setlocal EnableExtensions
chcp 65001 >nul 2>&1
cd /d "%~dp0"

if not exist "%~dp0scripts\wowmod-start.ps1" goto noscript

set "WM_ARG=%~1"

rem 注意：拖放时 "%~1" 已经去掉了外层引号，这里必须自己补回来，
rem 否则 "D:\Midnight Open Beta\..." 到 PowerShell 那边又会被拆成多段。
if defined WM_ARG (
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0scripts\wowmod-start.ps1" "%WM_ARG%"
) else (
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0scripts\wowmod-start.ps1"
)
set "WM_RC=%errorlevel%"

if not "%WM_RC%"=="0" (
  echo.
  echo  [提示] PowerShell 退出码 %WM_RC%
  echo         若上一行没有任何输出，说明 PowerShell 被策略阻止或找不到。
  echo         可尝试：右键本文件 -> 以管理员身份运行
  echo.
  pause
)
endlocal
exit /b 0

:noscript
echo.
echo  [失败] 缺少 scripts\wowmod-start.ps1
echo         请确认本文件与 scripts 文件夹在同一个目录（仓库根目录）。
echo.
pause
exit /b 1
