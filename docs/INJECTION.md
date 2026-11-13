# 注入机制与客户端启动排错（历史记录；不证明替换加载成功）

> **状态核对：**用户提供的日志显示 LoadLibraryW / NtCreateThreadEx 线程退出码为 0 但模块表未见 DLL、APC 3 秒未进入 alertable wait、SetWindowsHookExW 失败 87，程序报告终止客户端。这些结果不证明注入成功，也不足以认定客户端有反注入保护。当前源码在 `keepClientOnInjectFailure=true` 时应恢复客户端；若实际运行却终止，必须先核对实际 exe 与配置，不能把源码行为当成该次运行事实。
>
> 本页其余内容记录此前注入排错实现；它不等于当前 Arctium 风格 FileDataID hook 已实现。当前加载器状态见 [ARCTIUM-STYLE.md](ARCTIUM-STYLE.md)。只用于你有权修改/调试的私服或离线环境。

## 用户已提供的注入日志（仅代表该次尝试）

- LoadLibraryW 线程退出码为 `0x00000000`，但目标进程模块表未出现 DLL。
- NtCreateThreadEx 线程退出码为 `0x00000000`，但目标进程模块表未出现 DLL。
- APC 已排队；等待 3 秒后没有观察到目标线程进入 alertable wait。
- x64 / PE 预检与依赖检查报告通过。
- `SetWindowsHookExW` 失败，错误 87；程序报告终止客户端。

线程退出码 `0` 和本地预检通过都不是目标 DLL 已在游戏进程初始化的证明；错误 87 也不足以判断客户端存在保护。日志没有确认 hook 安装或资源读取。

当前活动分支的源代码在 `keepClientOnInjectFailure=true` 时应恢复客户端；这与用户报告的“已终止客户端”不一致。实际运行的 exe、配置和源码版本尚未核对，故不能说该次运行符合当前源代码行为，也不应据此推断保护机制。
## 本次修正：DLL 初始化不再阻塞 Windows loader lock

此前 DLL 的 `DllMain(DLL_PROCESS_ATTACH)` 里直接读取配置、扫描文件、安装 IAT hooks、
启动内存扫描线程。Windows 在 `DllMain` 期间持有 loader lock；这类耗时/会加载库的
工作放在这里有死锁和初始化时序风险。

当前分支已改成：`DllMain` 只创建一个初始化 worker 并立即返回；配置读取与 overlay hook
安装在 worker 中执行。新增 `wowmod_init_status` 导出（0 初始化中、1 runtime 初始化完成、
-1 初始化失败、-2 worker 创建失败、2 诊断探测跳过）。此外，诊断输出已改成准确说明
`WOWMOD_PROBE` 会跳过 overlay 初始化，不再把它说成完整 DllMain 验证；恢复主线程后的
Windows hook 重试结果也会列在失败输出中。

这一修改降低了 loader-lock 风险，但**还没有在真实 Windows / Firestorm 12.0.7 上验证能成功注入**，
不能把它当作已解决。

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
