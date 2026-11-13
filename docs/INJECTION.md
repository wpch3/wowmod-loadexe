# 注入机制与客户端启动排错

> 这份文档针对 12.0.7 Firestorm / `wow_loader.dll` 加密壳客户端。
> 只用于你有权修改/调试的私服或离线环境。

## 已经确认的事实（来自真机输出）

```
目标进程 GetLastError=0 （无错误）
本地 PE 映射预检通过（x64/格式正确）
本进程完整加载成功（DllMain + 依赖都正常）
依赖: [OK] KERNEL32.dll
```

用户报告直接双击游戏可启动，`launch` 的注入尝试失败；此前把进程移到 `D:\`、
提高权限并重试后仍失败。当前日志显示 PE 映射通过、本进程完整加载成功，而目标进程
模块表未出现 DLL。可以判断 DLL 自身大概率正常、当前注入尝试没有成功；但还不能据此断言
是客户端反注入：远程线程退出码 `0` 不是完整的 64 位 `HMODULE`；
`NtCreateThreadEx` 的退出码也不能直接当作 `LoadLibraryW` 返回值。
`GetLastError=0` 只说明采样到的线程/调用上下文没有保留 Win32 错误，不能证明
存在 `LoadLibraryW` hook。`SetWindowsHookExW` 的错误 87 是 `ERROR_INVALID_PARAMETER`，
需要在 GUI 线程已运行后重试，不能直接归因于游戏保护。

- DLL 能在加载器进程完整加载、PE 映射检查通过、依赖可见；所以 DLL 文件本身问题
  的可能性较低，但最终原因尚未实机确定。
- 直接双击客户端可以启动，说明客户端本身可运行。此前 `launch` 在注入失败后调用
  `TerminateProcess`，会把语言选择框/游戏一起关掉；这属于启动器行为，不是你选错
  语言或游戏 exe 坏了。新版默认在注入失败后恢复客户端继续运行，并明确显示
  「模组覆盖未加载」，不再杀掉游戏；配置 `keepClientOnInjectFailure=false`
  可恢复严格失败行为。

## 当前自动轮换的注入机制

`launch` 会依次尝试，并且**一律用「目标进程模块表里是否出现 wowmod_hook.dll」
作为成功判据**（不再看 32 位线程退出码）：

| 机制 | 做法 | 绕过什么 |
| --- | --- | --- |
| `loadlibrary` | `CreateRemoteThread` → `LoadLibraryW` | 经典方式，基线 |
| `ntcreatethreadex` | ntdll `NtCreateThreadEx` → `LoadLibraryW` | kernel32 层被 hook / `CreateRemoteThread` 被拦 |
| `apc` | `QueueUserAPC` 排到客户端主线程，等它进入 alertable wait | 保护只针对"新建远程线程" |
| `windowshook` | `SetWindowsHookExW(WH_GETMESSAGE)` 让 **user32** 自己把 DLL 带进目标进程 | 保护只针对远程 `LoadLibraryW` 调用；完全不创建远程线程 |

`windowshook` 需要加载器进程保持存活（钩子由它持有），所以该方式成功后
`wowmod.exe` 会**一直等到游戏退出才返回命令行** —— 这是正常的，不是卡死。
如果注入失败，新版默认让客户端继续启动（但不加载模组覆盖），以免误杀原游戏；
输出会明确写「注入失败；已让客户端继续启动（模组覆盖未加载）」。

配置：

```jsonc
"injectMethods": ["loadlibrary", "ntcreatethreadex", "apc"],
"injectWindowsHook": true,
"injectRetry": true,
"injectRetryAttempts": 3,
"injectRetryDelayMs": 1000
```

## 如果四种都失败

这只能说明这些注入路径没有成功，**不能单凭此输出认定客户端有反注入保护**。
先看恢复 GUI 线程后 `SetWindowsHookExW` 是否成功、错误码是什么，再核对
客户端的正式启动入口/游戏进程命令行。若能确认客户端确实禁止外部加载，优先找
客户端支持的插件/覆盖机制；不要绕过其安全限制。

1. **使用客户端/私服提供的正式插件或覆盖机制**（如有），这是首选。
2. **纯 VFS / 资源文件覆盖**：保留客户端自身的启动与加载流程；不需要注入 DLL，
   但能否适用取决于客户端资源加载方式。

不会在没有客户端所有者授权/明确支持的情况下，继续实现绕过保护的手动映射。

## 需要你发回的东西

你已经提供了直接双击可启动、任务管理器中一个进程、没有反作弊这三点，**不用重复**。
若新版仍注入失败，请只补充：

1. 新版 `launch` 输出末尾的完整失败段（尤其客户端线程恢复后 `SetWindowsHookExW` 的结果）。
2. `diagnose-load.ps1` 是可选项；游戏目录包版本在根目录：
   ```powershell
   Test-Path .\diagnose-load.ps1
   powershell -ExecutionPolicy Bypass -File .\diagnose-load.ps1
   ```
   源码仓库 ZIP 才用 `powershell -ExecutionPolicy Bypass -File .\scripts\diagnose-load.ps1`。
   你之前的错误只表示当前 `D:\wowmod-loadexe` 目录没有 `scripts\diagnose-load.ps1`，
   不代表 DLL 加载失败；launch 已报告本进程完整加载成功，因此不用为了它再下载源码目录。

**可选但有用**：`wowmod.log`、任务管理器里客户端进程的"命令行/完整性级别"截图、
`wow_loader.dll` 有没有数字签名（右键属性）。

**不要发**：账号、密码、登录器本体、反作弊程序文件。

## 判断成功的标志

- 成功时输出 `注入成功（xxx）` 或 `Windows 钩子注入成功`，并打印 `已启动客户端 PID …`。
- 成功后 `examples\12.0.7\runtime-dumps\`（或游戏目录下 `runtime-dumps\`）会生成
  解密后的 `.img` 和 `*.candidates.json` —— **把这个目录发我**即可收尾最后一条
  FileDataID hook 点。
- 若输出 `注入失败；已让客户端继续启动（模组覆盖未加载）`，客户端仍会打开，
  但覆盖层没有加载；不要把它当作模组功能已生效。
