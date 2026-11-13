# 注入机制与「客户端拒绝注入」排错

> 这份文档针对 12.0.7 Firestorm / `wow_loader.dll` 加密壳客户端。
> 只用于你有权修改/调试的私服或离线环境。

## 已经确认的事实（来自真机输出）

```
目标进程 GetLastError=0 （无错误）
本地 PE 映射预检通过（x64/格式正确）
本进程完整加载成功（DllMain + 依赖都正常）
依赖: [OK] KERNEL32.dll
```

四条命令全成功、只有 `launch` 失败；移到 `D:\`、管理员权限、4 次重试结果完全一致。
由此可以确定：

- **`wowmod_hook.dll` 本身完全正常**：位数、PE 结构、导入、DllMain 初始化都没问题，
  在加载器自己的进程里能完整加载。
- **失败发生在「跨进程注入」这一层**，不是文件、路径、依赖或位数问题。
- `GetLastError=0` 是最关键的线索：`LoadLibraryW` 若正常失败一定会设置非 0 错误码
  （126/5/193/1114…）。返回 NULL 却不设错误码，通常是**目标进程里有人 hook 了
  `LoadLibraryW`/`LdrLoadDll` 并对不在白名单里的 DLL 静默返回 NULL** —— 这是
  带保护/加壳客户端的常见行为；也可能是远程代码没有真正执行（CFG/ACG 拦截）。
- 换目录、加 Defender 排除项对这种情况**不会有帮助**。

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

配置：

```jsonc
"injectMethods": ["loadlibrary", "ntcreatethreadex", "apc"],
"injectWindowsHook": true,
"injectRetry": true,
"injectRetryAttempts": 3,
"injectRetryDelayMs": 1000
```

## 如果四种都失败

说明客户端的加载层对**任何外部注入**都有防护（模块签名/白名单）。
剩下两条路，需要你补充信息后我再实现：

1. **手动映射 / Reflective DLL Injection**：自己把 DLL 映射进目标进程、
   解析导入、重定位、调用 DllMain，完全不经过 `LoadLibraryW`。能绕过模块白名单，
   但仍需要一段远程可执行代码，可能受 CFG/ACG 限制；实现量较大。
2. **让客户端自己加载**：如果这个私服客户端有官方的插件/模组加载机制
   （比如扫描某个目录里的 DLL），可以直接接入，比对抗保护更稳。

## 需要你发回的东西

**最少只要这 3 项：**

1. **新版 `launch` 的完整输出**（会自动列出每种机制的结果，例如
   `ntcreatethreadex: ... -> 模块表未出现`）。这能告诉我们哪一种机制还有机会。
2. **`diagnose-load.ps1` 的输出**（前面几轮一直没跑，它验证本进程侧）：
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\diagnose-load.ps1
   ```
3. **客户端启动方式的一句话说明**：
   - 直接双击 `WoW 12.0.7 - Firestorm.exe` 能不能正常进游戏？
   - 是否有单独的登录器 / 反作弊程序 / "Eidolon" 之类保护提示？
   - 启动后任务管理器里是**一个进程还是多个**（有些壳会再拉起真正的游戏进程）。

**可选但有用**：`wowmod.log`、任务管理器里客户端进程的"命令行/完整性级别"截图、
`wow_loader.dll` 有没有数字签名（右键属性）。

**不要发**：账号、密码、登录器本体、反作弊程序文件。

## 判断成功的标志

- 成功时输出 `注入成功（xxx）` 或 `Windows 钩子注入成功`，并打印 `已启动客户端 PID …`。
- 成功后 `examples\12.0.7\runtime-dumps\`（或游戏目录下 `runtime-dumps\`）会生成
  解密后的 `.img` 和 `*.candidates.json` —— **把这个目录发我**即可收尾最后一条
  FileDataID hook 点。
- 只要还出现 `注入失败，已终止客户端`，就说明覆盖层没进去，此时不要进游戏。
