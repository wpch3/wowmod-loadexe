# wowmod 一键启动器（逻辑部分，由 wowmod-start.cmd 调用）
#
# 目的：不再让人手敲命令行。它会：
#   1. 自己找到游戏 exe（拖放 / 自动搜索 / 弹窗选择）
#   2. 检查 4 个文件是否齐全
#   3. 让你用一个数字选模式
#   4. 跑完自动打开报告
#
# 手动等价命令（仅供排查）：
#   wowmod_loader.exe --exe "<游戏exe>" --mode observe

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptRoot          # 仓库根目录
$ConfigFile = Join-Path $Root 'wowmod-client-path.txt'

function Line { param([string]$t = '') Write-Host $t }
function Head { param([string]$t) Write-Host ''; Write-Host ('=' * 62); Write-Host "  $t"; Write-Host ('=' * 62) }
function Ok   { param([string]$t) Write-Host "  [OK]   $t" -ForegroundColor Green }
function Warn { param([string]$t) Write-Host "  [警告] $t" -ForegroundColor Yellow }
function Bad  { param([string]$t) Write-Host "  [失败] $t" -ForegroundColor Red }
function Info { param([string]$t) Write-Host "         $t" -ForegroundColor DarkGray }

# ---------------------------------------------------------------- 找文件
function Find-Loader {
  $cands = @(
    (Join-Path $Root 'wowmod_loader.exe'),
    (Join-Path $Root 'dist\windows-x64\wowmod_loader.exe'),
    (Join-Path $ScriptRoot 'wowmod_loader.exe')
  )
  foreach ($c in $cands) { if (Test-Path -LiteralPath $c) { return $c } }
  return $null
}

function Find-Runtime {
  param([string]$LoaderPath)
  $dir = Split-Path -Parent $LoaderPath
  foreach ($c in @((Join-Path $dir 'wowmod_rt.dll'), (Join-Path $Root 'wowmod_rt.dll'),
                   (Join-Path $Root 'dist\windows-x64\wowmod_rt.dll'))) {
    if (Test-Path -LiteralPath $c) { return $c }
  }
  return $null
}

# ---------------------------------------------------------------- 找游戏 exe
function Test-GameExe {
  param([string]$Path)
  if (-not $Path) { return $false }
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
  if ([IO.Path]::GetExtension($Path) -ne '.exe') { return $false }
  $name = [IO.Path]::GetFileName($Path)
  # 排除我们自己
  if ($name -match '^wowmod') { return $false }
  try {
    # 64 位 PE + 体积 > 10MB：WoW 客户端都满足，能挡掉大多数误选
    $fs = [IO.File]::OpenRead($Path)
    try {
      $br = New-Object IO.BinaryReader($fs)
      $fs.Position = 0x3C
      $lfanew = $br.ReadUInt32()
      $fs.Position = $lfanew + 4
      $machine = $br.ReadUInt16()
      $size = $fs.Length
    } finally { $fs.Close() }
    return ($machine -eq 0x8664 -and $size -gt 10MB)
  } catch { return $false }
}

function Find-GameExe {
  # 1) 上次记住的
  if (Test-Path -LiteralPath $ConfigFile) {
    $saved = (Get-Content -LiteralPath $ConfigFile -Raw -ErrorAction SilentlyContinue)
    if ($saved) { $saved = $saved.Trim(); if (Test-GameExe $saved) { return $saved } }
  }
  # 2) 仓库/脚本目录里
  foreach ($dir in @($Root, $ScriptRoot)) {
    $hit = Get-ChildItem -LiteralPath $dir -Filter '*.exe' -File -ErrorAction SilentlyContinue |
           Where-Object { Test-GameExe $_.FullName } | Select-Object -First 1
    if ($hit) { return $hit.FullName }
  }
  # 3) 常见位置（一层子目录）
  $roots = @()
  foreach ($d in [IO.DriveInfo]::GetDrives()) {
    if ($d.DriveType -in 'Fixed','Removable' -and $d.IsReady) { $roots += $d.RootDirectory.FullName }
  }
  $roots += @("$env:ProgramFiles", "$env:ProgramFiles (x86)", "$env:LOCALAPPDATA", 'C:\Games', 'D:\Games')
  foreach ($r in $roots) {
    if (-not (Test-Path -LiteralPath $r)) { continue }
    try {
      $subs = Get-ChildItem -LiteralPath $r -Directory -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -match 'midnight|wow|world of warcraft|firestorm|_retail_|_midnight_' }
      foreach ($s in $subs) {
        $hit = Get-ChildItem -LiteralPath $s.FullName -Filter '*.exe' -File -ErrorAction SilentlyContinue |
               Where-Object { Test-GameExe $_.FullName } | Select-Object -First 1
        if ($hit) { return $hit.FullName }
        foreach ($s2 in (Get-ChildItem -LiteralPath $s.FullName -Directory -ErrorAction SilentlyContinue)) {
          $hit = Get-ChildItem -LiteralPath $s2.FullName -Filter '*.exe' -File -ErrorAction SilentlyContinue |
                 Where-Object { Test-GameExe $_.FullName } | Select-Object -First 1
          if ($hit) { return $hit.FullName }
        }
      }
    } catch {}
  }
  return $null
}

function Pick-GameExe {
  Add-Type -AssemblyName System.Windows.Forms | Out-Null
  $dlg = New-Object System.Windows.Forms.OpenFileDialog
  $dlg.Title = '选择 WoW 客户端 exe（例如 WoW 12.0.7 - Firestorm.exe）'
  $dlg.Filter = '客户端程序 (*.exe)|*.exe'
  if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
  if (-not (Test-GameExe $dlg.FileName)) {
    Warn "选中的程序不像 64 位 WoW 客户端：$($dlg.FileName)"
    $yn = Read-Host '  仍然要用它吗？(y/N)'
    if ($yn -notmatch '^(y|Y)') { return $null }
  }
  return $dlg.FileName
}

function Save-GameExe { param([string]$Path)
  try { Set-Content -LiteralPath $ConfigFile -Value $Path -Encoding UTF8 } catch {}
}

# ---------------------------------------------------------------- 报告
function Show-Progress {
  param([string]$GameDir)
  if (-not $GameDir) { $GameDir = Split-Path -Parent $GameExe }
  $p = Join-Path (Join-Path $GameDir 'wowmod') 'wowmod-progress.log'
  if (Test-Path -LiteralPath $p) {
    $lines = Get-Content -LiteralPath $p -ErrorAction SilentlyContinue
    Ok "实时进度文件: $p（$($lines.Count) 行）"
    Line ''
    Info '--- 最后 30 行（程序卡住时这里就是它停的位置）---'
    $lines | Select-Object -Last 30 | ForEach-Object { "  $_" }
    Line ''
    Info '按回车打开文件本身'
    Read-Host | Out-Null
    try { Start-Process notepad.exe -ArgumentList "`"$p`"" } catch {}
  } else {
    Warn "还没有进度文件: $p"
    Info '需要先跑一次模式 1（分析会自动生成这个文件）'
  }
}

function Show-Report {
  param([string]$GameDir)
  $wow = Join-Path $GameDir 'wowmod'
  $txt = Join-Path $wow 'wowmod-analysis.txt'
  if (Test-Path -LiteralPath $txt) {
    Ok "分析报告: $txt"
    try { Start-Process notepad.exe -ArgumentList "`"$txt`"" } catch {}
  } else {
    Warn "还没有报告：$txt"
    Info '进到登录界面并停几秒后才会生成（运行时每 2 秒检查一次）。'
  }
  if (Test-Path -LiteralPath $wow) { try { Start-Process explorer.exe -ArgumentList "`"$wow`"" } catch {} }
}

function Show-InterceptLog {
  param([string]$GameDir)
  $log = Join-Path (Join-Path $GameDir 'wowmod') 'wowmod-intercept.log'
  if (Test-Path -LiteralPath $log) {
    $n = (Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | Measure-Object).Count
    Ok "拦截日志: $log（$n 行）"
    try { Start-Process notepad.exe -ArgumentList "`"$log`"" } catch {}
  } else {
    Warn "还没有拦截日志：$log"
    Info '需要：1) 用「拦截实测」模式启动  2) 走到登录界面  3) 让客户端真的去读文件'
  }
}

# ---------------------------------------------------------------- 传参
# PowerShell 5.1 的 Start-Process -ArgumentList 传【数组】时会直接用空格拼起来，
# 【不会】给含空格的参数加引号 ——
#   "D:\Midnight Open Beta\_midnight_\WoW 12.0.7 - Firestorm.exe"
# 会被切成 D:/Midnight Open Beta/... 然后客户端只收到 "D:/Midnight"。
# 所以这里自己拼成一条带引号的命令行字符串。
function Join-ArgLine {
  param([string[]]$Items)
  # 用 [char]34 表示双引号：PowerShell 单引号字符串里写 \" 是两个字符，
  # 不同版本行为容易搞错，直接用字符码最稳。
  $q = [char]34
  $parts = @()
  foreach ($a in $Items) {
    if ($null -eq $a) { continue }
    $t = [string]$a
    if ($t.Length -eq 0) { $parts += ($q + $q); continue }
    if ($t -match '[\s"]') {
      $inner = $t -replace '"', ('\' + $q)
      $parts += ($q + $inner + $q)
    } else {
      $parts += $t
    }
  }
  return ($parts -join ' ')
}

# ---------------------------------------------------------------- 自检
function Invoke-SelfTest {
  param([string]$Loader, [string]$Runtime)
  Head '自检'
  $cli = Join-Path (Split-Path -Parent $Loader) 'wowmod.exe'
  if (-not (Test-Path -LiteralPath $cli)) { $cli = Join-Path $Root 'wowmod.exe' }
  if (-not (Test-Path -LiteralPath $cli)) { $cli = Join-Path $Root 'dist\windows-x64\wowmod.exe' }

  if (Test-Path -LiteralPath $cli) {
    Ok "wowmod.exe: $cli"
    try {
      $out = & $cli version 2>&1
      if ($LASTEXITCODE -eq 0) { Ok "能运行: $($out -join ' ')" }
      else { Bad "wowmod.exe 退出码 $LASTEXITCODE"; $out | ForEach-Object { "         $_" } }
    } catch { Bad "wowmod.exe 无法运行: $($_.Exception.Message)" }
  } else { Warn '没有 wowmod.exe（CLI 不是必需的）' }

  Ok "wowmod_loader.exe: $Loader"
  $caps = Get-LoaderCapabilities -Loader $Loader
  if ($caps.Tag -ne '') {
    Ok "启动器版本 $($caps.Tag)，支持模式: $($caps.Modes -join ' / ')"
  } else {
    Warn '启动器 --version 无响应 —— 这很可能是旧版本 exe'
  }
  $loaderDir = Split-Path -Parent $Loader
  $rtBeside = Join-Path $loaderDir 'wowmod_rt.dll'
  if (Test-Path -LiteralPath $rtBeside) { Ok "wowmod_rt.dll 与启动器同目录" }
  else {
    Warn 'wowmod_rt.dll 不在启动器同目录（启动时会自动复制）'
    if ($Runtime) { Info "将从 $Runtime 复制" }
  }
  try {
    $out = & $Loader --help 2>&1
    if ($LASTEXITCODE -eq 0) { Info '启动器可正常执行 --help' }
    else { Bad "启动器 --help 退出码 $LASTEXITCODE"; $out | ForEach-Object { "         $_" } }
  } catch { Bad "启动器无法运行: $($_.Exception.Message)"; Info '若提示缺少 VCRUNTIME/UCRT，请安装 VC++ 运行库' }

  Line ''
  Info '以上三项都 OK，说明二进制在你的机器上能跑 —— 剩下的只是客户端路径和模式选择。'
}

# ---------------------------------------------------------------- 主流程
# 读 loader 自带的能力清单（--version 输出）。
# 目的：脚本和 exe 版本不一致时当场说清楚，而不是让旧 exe 静默按默认模式跑。
function Get-LoaderCapabilities {
  param([string]$Loader)
  $caps = @{ Tag = ''; Modes = @() }
  try {
    $out = & $Loader --version 2>&1
    foreach ($line in $out) {
      if ($line -match 'build:\s*(\S+)') { $caps.Tag = $Matches[1] }
      if ($line -match 'modes:\s*(.+)') { $caps.Modes = $Matches[1].Trim().Split(' ') }
    }
  } catch { }
  return $caps
}

function Assert-ModeSupported {
  param([string]$Loader, [string]$Mode)
  $caps = Get-LoaderCapabilities -Loader $Loader
  if ($caps.Tag -eq '') {
    Warn '无法读取启动器版本（--version 无响应），跳过模式兼容性检查。'
    return $true
  }
  Info "启动器版本: $($caps.Tag)"
  if ($caps.Modes -notcontains $Mode) {
    Bad "这个启动器不支持模式 '$Mode'（它支持: $($caps.Modes -join ' / ')）"
    Info '说明 zip 里的 wowmod_loader.exe 和 wowmod-start.ps1 不是同一批产物。'
    Info '请重新解压完整的 zip（不要只替换其中几个文件），或运行菜单 8 自检。'
    return $false
  }
  return $true
}

function Invoke-Mode {
  param([string]$GameExe, [string]$Loader, [string]$Runtime, [string]$Mode, [string]$Label,
        [string]$ExtraArgs = '')

  $GameDir = Split-Path -Parent $GameExe
  $GameDirWowmod = Join-Path $GameDir 'wowmod'
  if (-not (Test-Path -LiteralPath $GameDirWowmod)) {
    New-Item -ItemType Directory -Path $GameDirWowmod -Force | Out-Null
  }
  Save-GameExe $GameExe

  Head "启动（$Label）"
  Info "游戏: $GameExe"
  Info "模式: $Mode"
  Line ''
  if (-not (Assert-ModeSupported -Loader $Loader -Mode $Mode)) { return }
  Line ''

  # 运行时 DLL 必须在 loader 同目录（loader 按自身目录找它）
  $loaderDir = Split-Path -Parent $Loader
  $runtimeBeside = Join-Path $loaderDir 'wowmod_rt.dll'
  if (-not (Test-Path -LiteralPath $runtimeBeside)) {
    Copy-Item -LiteralPath $Runtime -Destination $runtimeBeside -Force
    Info "已把 wowmod_rt.dll 放到 $loaderDir"
  }

  # 清掉旧日志，免得看到上次的结果
  $oldLog = Join-Path $GameDirWowmod 'wowmod_rt.log'
  if (Test-Path -LiteralPath $oldLog) { Remove-Item -LiteralPath $oldLog -Force -ErrorAction SilentlyContinue }
  $beacon = Join-Path $GameDirWowmod 'wowmod_beacon.txt'
  if (Test-Path -LiteralPath $beacon) { Remove-Item -LiteralPath $beacon -Force -ErrorAction SilentlyContinue }

  if (-not (Test-Path -LiteralPath $GameExe -PathType Leaf)) {
    Bad "客户端路径不存在（可能被移动/改名）: $GameExe"
    return
  }
  # 默认走"零模块"模式（不加载任何 DLL），这是唯一不会触发
  # 客户端 0x1100「检测到不受支持的软件」的路径。
  $argList = @('--exe', $GameExe, '--mode', $Mode, '--wait', '120000')
  if ($ExtraArgs) { $argList += $ExtraArgs.Split(' ') }
  $loaderArgs = Join-ArgLine $argList
  Info "命令行: `"$Loader`" $loaderArgs"
  Line ''
  $p = Start-Process -FilePath $Loader -ArgumentList $loaderArgs -WorkingDirectory $loaderDir `
                     -Wait -PassThru -NoNewWindow
  $code = $p.ExitCode
  Line ''
  switch ($code) {
    0 { Ok '启动器返回成功。' }
    2 { Bad '找不到客户端文件（路径不对）。'; return }
    4 { Bad '缺少 wowmod_rt.dll。'; return }
    5 { Bad '无法在客户端进程里写内存（权限不足？试试以管理员身份运行）。'; }
    6 { Bad '把 wowmod_rt.dll 载入客户端失败（加载路径被拒绝）。'; }
    7 { Bad '客户端在启动后立刻退出了 —— 载入运行时导致崩溃。'; }
    default { Warn "启动器退出码 $code。" }
  }

  # 先看 beacon：它证明「代码真的进了客户端进程」
  Line ''
  if (Test-Path -LiteralPath $beacon) {
    Ok '运行时已进入客户端进程（beacon 已生成）'
  } else {
    Info 'beacon 不存在（零模块模式下这是正常的：我们没有加载任何 DLL）'
    Info "看下面启动器打印的 [成功]/[失败] 行。"
  }
  $attempts = Join-Path $GameDirWowmod 'load-attempts.txt'
  if (Test-Path -LiteralPath $attempts) {
    Line ''
    Info '--- 三条加载路径的结果 ---'
    Get-Content -LiteralPath $attempts -ErrorAction SilentlyContinue | ForEach-Object { "  $_" }
  }
  if (Test-Path -LiteralPath $oldLog) {
    Info '--- wowmod_rt.log 最后 25 行 ---'
    Get-Content -LiteralPath $oldLog -Tail 25 -ErrorAction SilentlyContinue | ForEach-Object { "  $_" }
  } elseif (Test-Path -LiteralPath $beacon) {
    Warn 'beacon 有了但 log 没写出来 —— DLL 内部初始化中断（把这段发我）'
  }

  Line ''
  # 分析是启动器【同步】做完的（不需要进游戏、不需要等）。
  $txt = Join-Path $GameDirWowmod 'wowmod-analysis.txt'
  if (Test-Path -LiteralPath $txt) {
    $sz = (Get-Item -LiteralPath $txt).Length
    Ok "分析报告已生成（$sz 字节）"
    Show-Report $GameDir
  } else {
    Bad '没有生成分析报告'
    Info '最可能的原因：读内存被拒绝 / 客户端还没解密完。'
    Info '把上面启动器打印的『扫描』和『可扫描区域』那几行发我。'
  }

  # 各模式自己的后续动作（和上面报告是否生成无关）
  if ($Mode -eq 'auto') {
    Info '拦截器已装好（只记录调用参数，不改变客户端任何行为）。'
    Info '请按顺序做，让它多被调用几次：'
    Info '  1) 停在登录界面 10 秒'
    Info '  2) 进角色选择'
    Info '  3) 进一次游戏'
    Info '然后回这个窗口按回车 —— 启动器会停止轮询并在 notepad 里打开记录。'
    Read-Host | Out-Null
    Show-InterceptLog $GameDir
  } elseif ($Mode -eq 'diagnose') {
    $dg = Join-Path $GameDirWowmod 'wowmod-diagnose.txt'
    if (Test-Path -LiteralPath $dg) {
      Ok "诊断完成: $dg"
      try { Start-Process notepad.exe -ArgumentList "`"$dg`"" } catch {}
    } else { Bad '没生成诊断文件' }
  } elseif ($Mode -eq 'hook') {
    Info 'hook 模式已启动。进游戏检查贴图是否变化。'
    Show-Report $GameDir
  }
}

# ================================================================ 入口
Clear-Host
Head 'wowmod 一键启动器 — WoW 12.0.7 松散文件加载'

# 1) 拖放进来的参数优先
$GameExe = $null
if ($args.Count -ge 1 -and $args[0]) {
  $cand = ([string]$args[0]).Trim('"').Trim()
  if (Test-Path -LiteralPath $cand -PathType Leaf) {
    if ([IO.Path]::GetExtension($cand) -eq '.exe') { $GameExe = $cand }
    else {
      # 拖进来的是文件夹：在里面找
      $hit = Get-ChildItem -LiteralPath $cand -Filter '*.exe' -File -ErrorAction SilentlyContinue |
             Where-Object { Test-GameExe $_.FullName } | Select-Object -First 1
      if ($hit) { $GameExe = $hit.FullName }
    }
  }
}
# 大硬盘上无差别递归会很慢，所以这里只在「上次记住的路径」和常见目录找；
# 实在找不到就弹窗让你选，绝不让你手敲路径。
if (-not $GameExe) { $GameExe = Find-GameExe }
if (-not $GameExe) {
  Warn '没有自动找到客户端 exe。'
  $yn = Read-Host '  现在弹窗手动选择？(Y/n)'
  if ($yn -notmatch '^[nN]') { $GameExe = Pick-GameExe }
}
if (-not $GameExe) { Bad '没有客户端路径，退出。'; Read-Host '按回车关闭' | Out-Null; return }

$Loader = Find-Loader
if (-not $Loader) { Bad "找不到 wowmod_loader.exe（应在 $Root）"; Read-Host '按回车关闭' | Out-Null; return }
$Runtime = Find-Runtime -LoaderPath $Loader
if (-not $Runtime) { Bad '找不到 wowmod_rt.dll'; Read-Host '按回车关闭' | Out-Null; return }

Ok "客户端: $GameExe"
Ok "启动器: $Loader"
Ok "运行时: $Runtime"
Save-GameExe $GameExe

# 2) 菜单
while ($true) {
  Head '选择要做什么'
  Line '  1  观察分析（只读，不改客户端任何字节）        <- 想了解现状跑这个'
  Line '  2  特征码扫描 + 导出主模块（解密后的代码）    <- 现在跑这个'
  Line '  3  演练验证（不改客户端字节，只验证能否 hook）  <- 安全'
  Line '  4  真正安装拦截（会改客户端内存里的代码）      <- 有崩溃风险'
  Line '  5  查看分析报告'
  Line '  6  查看拦截日志'
  Line '  7  重新选择客户端 exe'
  Line '  8  自检（确认 4 个程序能在本机运行）'
  Line '  9  完整诊断'
  Line '  p  实时进度'
  Line '  0  退出'
  Line ''
  $c = Read-Host '  输入数字'
  # 空输入（比如用户直接按回车、或按住回车）不要刷屏；
  # 也不要把它当成"输入错误"死循环 —— 直接重画菜单即可。
  if ([string]::IsNullOrWhiteSpace($c)) { continue }
  switch ($c.Trim()) {
    '1' { Invoke-Mode -GameExe $GameExe -Loader $Loader -Runtime $Runtime -Mode 'observe'  -Label '观察分析（只读）' }
    '2' { Invoke-Mode -GameExe $GameExe -Loader $Loader -Runtime $Runtime -Mode 'sigscan'  -Label '特征码扫描 + 导出主模块' -ExtraArgs '--dump-module' }
    '3' { Invoke-Mode -GameExe $GameExe -Loader $Loader -Runtime $Runtime -Mode 'auto'     -Label '演练验证（不改客户端）' -ExtraArgs '--dry-run' }
    '4' {
      Warn '真正安装会改写客户端进程内的指令字节（只在内存里，不动磁盘文件）。'
      $yn = Read-Host '  确定继续？(y/N)'
      if ($yn -match '^(y|Y)') {
        Invoke-Mode -GameExe $GameExe -Loader $Loader -Runtime $Runtime -Mode 'auto' -Label '真正安装拦截（有风险）' -ExtraArgs '--apply'
      }
    }
    '5' { Show-Report (Split-Path -Parent $GameExe) }
    '6' { Show-InterceptLog (Split-Path -Parent $GameExe) }
    '7' { $g = Pick-GameExe; if ($g) { $GameExe = $g; Save-GameExe $g; Ok "已切换: $GameExe" } }
    '8' { Invoke-SelfTest -Loader $Loader -Runtime $Runtime }
    '9' { Invoke-Mode -GameExe $GameExe -Loader $Loader -Runtime $Runtime -Mode 'diagnose' -Label '完整诊断' }
    'p' { Show-Progress }
    '0' { return }
    default { Warn '请输入 0-9 或 p' }
  }
}
