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

## 方式 A：重新下载分支 ZIP（推荐，不用装编译器）

**现在分支里已经带上了预编译的 x64 二进制**（`wowmod.exe` + `wowmod_hook.dll`，
约 1 MB 各一个）。你截图里那份 ZIP 是旧版本，没有这两个文件。

1. 重新下载当前分支 ZIP 并解压，或直接单独下载这两个文件：

   - 分支 ZIP：<https://github.com/wpch3/wowmod-loadexe/archive/refs/heads/arena/5a3768a5-wowmod-loadexe.zip>
   - 单个 exe：<https://github.com/wpch3/wowmod-loadexe/raw/arena/5a3768a5-wowmod-loadexe/wowmod.exe>
   - 单个 DLL：<https://github.com/wpch3/wowmod-loadexe/raw/arena/5a3768a5-wowmod-loadexe/wowmod_hook.dll>
   - Release 说明页：<https://github.com/wpch3/wowmod-loadexe/releases/tag/windows-x64-afbfb94>

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
| `plan` 显示 `hook 模式: vfs` | **正常**，加密壳客户端的安全回退；路径型覆盖照常生效 |
| `runtime-dumps` 没生成 | 确认 `hooks.runtimeScan: true`；等 `runtimeDelayMs`（默认 4 秒）之后再看；目录相对配置文件所在目录 |

## x64dbg 怎么做

见 [`docs/X64DBG.md`](X64DBG.md)。**最简单路径其实是用上面的 `launch`**：加载器自己会转储解密后的内存，不需要手工调试器；x64dbg 只在需要人工确认"ID 寄存器 + 返回值语义"时才用到。

---

仅用于你有权修改/调试的私服或离线环境；不要用于官方服，也不要上传账号、登录器或反作弊相关文件。
