# Windows / PowerShell 快速开始（解决 "无法将 wowmod 项识别为 cmdlet"）

## 截图里为什么报错

```
PS ...> wowmod launch --config examples/12.0.7/wowmod.firestorm.json
无法将"wowmod"项识别为 cmdlet、函数、脚本文件或可运行程序的名称。
```

两个原因叠加：

1. **PowerShell 默认不搜索当前目录**。就算 `wowmod.exe` 在旁边，也必须写
   `.\wowmod.exe`（或完整路径），不能只写 `wowmod`。
2. **你下载的是 GitHub 分支源码 ZIP，里面根本没有 `wowmod.exe`**。仓库的
   `.gitignore` 排除了 `*.exe` / `*.dll`，编译产物不入库，只能自己编译或用预编译包。

所以 `.\wowmod.exe` 现在也会报"无法识别"——文件不存在。按下面任选一条补齐。

### 如果你已经 `cd` 到游戏目录

`PS D:\Midnight Open Beta\_midnight_>` 说明当前目录是**游戏目录**，不是你解压源码的
`C:\Users\Administrator\Downloads\Compressed\...`。`.\` 永远指"当前目录"，
所以先确认文件到底在哪：

```powershell
Get-Location
Test-Path .\wowmod.exe                       # False 就是没放对地方
Get-ChildItem -Name wowmod*                   # 看看当前目录有没有
```

三个选择：
1. **把预编译文件复制/解压到游戏目录**（方式 0，最省事）；
2. `cd` 回你解压源码的那个文件夹，再跑 `.\wowmod.exe …`；
3. 用**绝对路径**调用，不动当前目录：

   ```powershell
   & "C:\Users\Administrator\Downloads\Compressed\wowmod-loadexe-arena-5a3768a5-wowmod-loadexe\wowmod-loadexe-arena-5a3768a5-wowmod-loadexe\wowmod.exe" version
   ```

   路径带引号时 PowerShell 要用 `&` 调用运算符。

## 从源码文件夹运行：一条龙复制粘贴（对应仓库根目录 `RUN.txt`）

如果你已经在资源管理器里看到 `wowmod.exe` / `wowmod_hook.dll` 和 `examples\` 在一起
（截图里那种），**就在那个文件夹里打开 PowerShell**：点资源管理器地址栏，删掉路径，
输入 `powershell` 回车。然后整段复制：

```powershell
Unblock-File .\wowmod.exe, .\wowmod_hook.dll
.\wowmod.exe version
Test-Path "D:\Midnight Open Beta\_midnight_\WoW 12.0.7 - Firestorm.exe"
.\wowmod.exe detect   --config "examples\12.0.7\wowmod.firestorm.json"
.\wowmod.exe validate --config "examples\12.0.7\wowmod.firestorm.json"
.\wowmod.exe plan     --config "examples\12.0.7\wowmod.firestorm.json"
.\wowmod.exe launch   --config "examples\12.0.7\wowmod.firestorm.json"
```

预期：`version` → `wowmod-loadexe 1.0.0`；`Test-Path` → `True`；
`detect` → `12.0.7.68974 / x64 / 加载层 DLL: Wow_loader.dll / 已支持`；
`validate` → `校验通过`；`plan` → `hook 模式: vfs`（加密壳正常回退）。
`launch` 会真的启动游戏，别再手动双击 exe。

模组文件放 `examples\12.0.7\mods\models\`，里面路径就是游戏内路径；
按 FileDataID 覆盖写 `examples\12.0.7\mappings\listfile.txt`（`fileId;filePath`）。
放完再跑 `plan` 看覆盖表条数。完整说明见仓库根目录 **`RUN.txt`**。

## 方式 0：解压到游戏目录（最省事，推荐你用这个）

你现在 PowerShell 停在 `D:\Midnight Open Beta\_midnight_>`，所以 `wowmod.exe`
必须**也在那个目录里**才能写 `.\wowmod.exe`。为这个场景专门做了一个包：

**下载 <https://github.com/wpch3/wowmod-loadexe/raw/arena/5a3768a5-wowmod-loadexe/wowmod-12.0.7-game-dir.zip>**

把里面的内容**直接**解压到 `D:\Midnight Open Beta\_midnight_\`
（不要再套一层 `wowmod-12.0.7-game-dir\` 子文件夹）。解压后该目录应该能直接看到：

```
wowmod.exe
wowmod_hook.dll
wowmod.firestorm.json     ← 配置文件在根目录，不是 examples\12.0.7\ 下
hooks\  mappings\  mods\
RUN.txt  WINDOWS-QUICKSTART.md  X64DBG.md
```

然后在 `D:\Midnight Open Beta\_midnight_>` 里执行：

```powershell
Unblock-File .\wowmod.exe, .\wowmod_hook.dll
.\wowmod.exe version
.\wowmod.exe detect   --config ".\wowmod.firestorm.json"
.\wowmod.exe validate --config ".\wowmod.firestorm.json"
.\wowmod.exe plan     --config ".\wowmod.firestorm.json"
.\wowmod.exe launch   --config ".\wowmod.firestorm.json"
```

**注意配置路径变了**：这个包里是 `--config ".\wowmod.firestorm.json"`，
不是 `examples\12.0.7\wowmod.firestorm.json`（那是源码目录里的位置）。
`launch` 成功后 `runtime-dumps\` 会生成在游戏目录下。

> 是的，你问的"是不是要把 zip 解压到游戏目录"——**用这个包就是这么做的**，
> 而且它把所有相对路径（`mods\`、`mappings\`、`hooks\`、日志、转储目录）都按
> 游戏目录摆好了，不用改配置。当然也可以不解压到游戏目录（见方式 A）。

## 方式 A：重新下载分支 ZIP（不用动游戏目录）

**现在分支里已经带上了预编译的 x64 二进制**（`wowmod.exe` + `wowmod_hook.dll`，
约 1 MB 各一个）。你截图里那份 ZIP 是旧版本，没有这两个文件。

1. 重新下载当前分支 ZIP 并解压，或直接单独下载这两个文件：

   - 分支 ZIP：<https://github.com/wpch3/wowmod-loadexe/archive/refs/heads/arena/5a3768a5-wowmod-loadexe.zip>
   - 单个 exe：<https://github.com/wpch3/wowmod-loadexe/raw/arena/5a3768a5-wowmod-loadexe/wowmod.exe>
   - 单个 DLL：<https://github.com/wpch3/wowmod-loadexe/raw/arena/5a3768a5-wowmod-loadexe/wowmod_hook.dll>
   - Release 说明页：<https://github.com/wpch3/wowmod-loadexe/releases/tag/windows-x64-d467d73>

   放到源码根目录（就是有 `README.md`、`examples\` 那一层）：

   ```
   wowmod.exe            ← 必须与下面这个 DLL 放同一目录
   wowmod_hook.dll
   examples\12.0.7\wowmod.firestorm.json
   ```

2. PowerShell 里先解除下载锁定（从网上下载的文件常见）：

   ```powershell
   Unblock-File .\wowmod.exe
   Unblock-File .\wowmod_hook.dll
   ```

3. 逐条验证（**注意 `.\`**）：

   ```powershell
   .\wowmod.exe version
   .\wowmod.exe detect   --config examples\12.0.7\wowmod.firestorm.json
   .\wowmod.exe validate --config examples\12.0.7\wowmod.firestorm.json
   .\wowmod.exe plan     --config examples\12.0.7\wowmod.firestorm.json
   .\wowmod.exe launch   --config examples\12.0.7\wowmod.firestorm.json
   ```

   `launch` 会启动游戏并在 `examples\12.0.7\runtime-dumps\` 写出内存映像与候选特征
   （前提：配置里 `hooks.runtimeScan` 为 `true`）。把这个目录发我即可做最后一步确认。

> 路径含空格时一定加引号：`--config "examples\12.0.7\wowmod.firestorm.json"`。
> 正斜杠 `examples/12.0.7/...` 也能用，但反斜杠更贴近 PowerShell 习惯。

### 启动前必须确认的两件事

- `examples\12.0.7\wowmod.firestorm.json` 里的
  `client.exe` / `client.gameDir` 是否就是你机器上的
  `D:\Midnight Open Beta\_midnight_\WoW 12.0.7 - Firestorm.exe`。路径不对会报
  "找不到客户端 exe"。
- `wow_loader.dll` 与 exe 在同一目录（客户端自身要求），以及
  `mods\models\` 里放了你自己的模型替换文件。`plan` 里覆盖表为 0 条是正常的，
  因为示例包里没有真实模组文件。

## 方式 B：自己编译（已有 Visual Studio / Build Tools）

```powershell
cmake -S . -B build -A x64 -DWOWMOD_BUILD_HOOK_DLL=ON
cmake --build build --config Release
Copy-Item build\Release\wowmod.exe, build\Release\wowmod_hook.dll .
.\wowmod.exe version
```

也可以用 MinGW-w64：`cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release`。
32 位客户端要用 32 位工具链（本项目预编译包是 x64，对应你这个 x64 客户端）。

## 中文输出乱码（PowerShell 默认 GBK）

`wowmod-loadexe 1.0.0 (閫氱敤鐗堟湰...)`、`鏋舵瀯: x64` 这类不是程序坏了，
是程序输出 UTF-8 而 Windows PowerShell 5.1 用代码页 936(GBK) 解码。**乱码不影响功能**，
日志里的 `12.0.7.68974` / `True` / `校验通过` 都能照常读。

现在 CLI 会自动检测控制台代码页并转码（控制台且非 `--json` 时），重新下载
`wowmod.exe` 即可正常显示中文。也可以手动统一编码：

```powershell
chcp 65001
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
```

`--json` 输出与重定向到文件时**始终**保持 UTF-8（保证 JSON 可解析）。

## `launch` 报 `LoadLibraryW 返回 NULL`

前四条命令都正常、只有 `launch` 失败时，说明**客户端进程里加载
`wowmod_hook.dll` 失败**（远程线程确实执行了，返回 0）。常见三类原因：

1. **挂起阶段 loader/UCRT 还没初始化完**（加壳客户端常见）；
2. **Windows Defender / ASR 规则**拦截从 `Downloads` 目录向另一个进程注入未签名 DLL；
3. DLL 位数不符 / 缺 VC++ 运行库 / 客户端有反注入保护。

已加入的处理：**自动延迟重试** —— 挂起阶段失败时先恢复主线程，等
`injectRetryDelayMs`（默认 600ms）让 loader 初始化完，再注入一次。配置里
`hooks.injectRetry: true`。若成功，启动信息会写明"已在进程初始化后重试成功"。

还失败就跑诊断脚本，它会给出真正的 Win32 错误码：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\diagnose-load.ps1
# 游戏目录包里则是
powershell -ExecutionPolicy Bypass -File .\diagnose-load.ps1
```

错误码含义：

| 码 | 含义 / 处理 |
| --- | --- |
| 126 `ERROR_MOD_NOT_FOUND` | 依赖缺失 → 装 [VC++ 2015–2022 x64 运行库](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist) |
| 193 / 216 | 位数不符 → 用 x64 的 `wowmod_hook.dll` |
| 5 `ERROR_ACCESS_DENIED` | Defender/ASR 或权限 → 以管理员运行、移出 Downloads、加 Defender 排除项 |
| 1114 `ERROR_DLL_INIT_FAILED` | `DllMain` 初始化失败 → 看 `wowmod.log` |
| 0（脚本里能加载成功） | 说明 DLL 本身没问题，是注入时机/安全策略 → 用延迟重试与上面的 1/2 项 |

实用建议：把 `wowmod.exe` + `wowmod_hook.dll` 放到简单路径（例如 `D:\wowmod\`），
并把该目录加入 Windows Defender 排除项；比放在 `Downloads\Compressed\...` 稳。

## 排错表

| 现象 | 原因 / 处理 |
| --- | --- |
| `无法将"wowmod"项识别为…` | 少了 `.\`，写 `.\wowmod.exe` |
| `无法将".\wowmod.exe"项识别为…` | 文件不在当前目录；`Get-ChildItem` 看一下，或重新下载分支 ZIP / 单独下载两个二进制 |
| `找不到 wowmod_hook.dll（应与 wowmod.exe 放在同一目录）` | 两个文件必须放一起；`find_hook_dll()` 只查 exe 同目录和当前目录 |
| `找不到客户端 exe` / `无法打开` | 配置里的 `D:\...` 路径与你机器不符，改 `client.exe` / `client.gameDir` |
| `LoadLibraryW 返回 NULL` | 位数不匹配（x64 客户端必须用 x64 DLL），或缺少系统运行库 |
| 提示缺 `api-ms-win-crt-*.dll` | 装 [VC++ 2015–2022 x64 运行库](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist)；Win10/11 一般自带 |
| SmartScreen / Defender 拦截 | `Unblock-File .\wowmod.exe`、`Unblock-File .\wowmod_hook.dll`，或右键属性 → 解除锁定 |
| 中文显示成 `閫氱敤鐗堟湰` | 见上面「中文输出乱码」；重新下载 exe 或 `chcp 65001` |
| `LoadLibraryW 返回 NULL` | 见上面专节；跑 `diagnose-load.ps1` 拿错误码 |
| `plan` 显示 `hook 模式: vfs` | **正常**，加密壳客户端的安全回退；路径型覆盖照常生效 |
| `runtime-dumps` 没生成 | 确认 `hooks.runtimeScan: true`；等 `runtimeDelayMs`（默认 4 秒）之后再看；目录相对配置文件所在目录 |

## x64dbg 怎么做

见 [`docs/X64DBG.md`](X64DBG.md)。**最简单路径其实是用上面的 `launch`**：加载器自己会转储解密后的内存，不需要手工调试器；x64dbg 只在需要人工确认"ID 寄存器 + 返回值语义"时才用到。

---

仅用于你有权修改/调试的私服或离线环境；不要用于官方服，也不要上传账号、登录器或反作弊相关文件。
