# 材料清单与完成状态（12.0.7 Firestorm）

## 已收到的 ✅ —— 文件齐全，不用再传了

| 文件 | 校验 |
| --- | --- |
| `WoW 12.0.7 - Firestorm.exe` | 73,463,504 字节；SHA-256 `e31066a9fd7f16fc…`；x64 PE32+；`12.0.7.68974` |
| `wow_loader.dll` | 39,514,832 字节；SHA-256 `020791224a4bcf82b…`；x64 DLL，导出 ordinal #1 |
| `*.7z.001~003` | 解压出的 exe 与完整 exe 哈希完全一致 |

`detect` 对真实 exe 的输出：

```
版本: 12.0.7.68974 (build 68974)
架构: x64 | 加载层 DLL: Wow_loader.dll
支持状态: 已支持（无版本白名单）
```

## DLL 到手后查明的决定性事实

**这个客户端磁盘上的代码是加密的。** 静态特征扫描在这里不可能成功，理由如下：

| 观察 | exe | wow_loader.dll |
| --- | --- | --- |
| `.text` 大小 | 53 MB | 31 MB |
| `.text` 采样熵 | **7.95–8.00 / 8** | 6.23–7.23（正常代码） |
| 零字节比例 | 0.4% | 8.5% |
| 常见 x64 函数序言片段 | 857 处 | 7658 处 |
| 游戏字符串 | 大量明文在 `.rdata` | 几乎全部剥离 |

- exe 的导入表**只有 `Wow_loader.dll` 一个 ordinal #1** → 它是启动壳。
- 但 exe 的 `.text` 不是代码，而是**高熵密文/压缩数据**（`2d 18 d1 12 99 96 8f b9 …`），
  `.rdata` 里却留着 `DBFilesClient`、`FileData ID %d %s`、`addons.txt` 等明文字符串。
- DLL 里甚至找不到这些字符串的 UTF-16/ASCII 版本，只有一个 PDB 路径
  `D:\Jenkins\workspace\eidolon-generator_main\wow_prod_workspace\...\loader.pdb`
  和 `.eid` / `.eidsig` 这类自定义节区。
- 实测 `wowmod discover` 对两个文件都是 `xrefCount=0`：不是工具没找到，而是**磁盘上确实没有可引用的明文代码**。

结论：**通用 VFS 模式已经完全可用**（IAT hook 文件 API 在运行时生效，与磁盘是否加密无关），
但「按 FileDataID 从 CASC 读模型」的 hook 点只能在**进程解密之后的内存里**找。
这一步无法靠上传更多文件来完成。

## 我已经实现的解法：运行时内存扫描

新增 `wowmod_hook.dll` 的后台扫描（`hooks.runtimeScan`）：

1. 注入后等 `runtimeDelayMs`（默认 4 秒）让壳完成解密；
2. 用 `VirtualQuery` + `ReadProcessMemory` 把主 exe 和 `wow_loader.dll` 的**内存映像**
   转储为「文件偏移 == RVA」的 `.img`（`PeImage(mapped=true)` 支持这种布局）；
3. 在内存映像上跑 `discover_hook_points(..., mapped=true)`：明文字符串、指针表、RIP 相对引用
   这时才真正存在；
4. 把候选特征写到 `runtime-dumps/*.candidates.json` 和 `runtime-report.json`；
5. **默认不自动下断点**（`runtimeAutoInstall: false`）—— 候选仍需确认函数语义。

离线分析这些转储（在任意机器上）：

```bash
wowmod discover --exe runtime-dumps/main.exe.img --mapped --emit hooks/patterns.runtime.json
wowmod scan     --exe runtime-dumps/main.exe.img --mapped --patterns hooks/patterns.runtime.json
```

`--mapped` 让加载器按 RVA=偏移解析内存映像；已在模拟解密映像上验证能找到唯一候选。

## 还需要的（不是文件，是一次真机运行）

> 运行命令前先看 **[../../docs/WINDOWS-QUICKSTART.md](../../docs/WINDOWS-QUICKSTART.md)**：
> 分支 ZIP 里现在已带编译好的 exe，PowerShell 必须写 `.\wowmod.exe`。
> **最省事**：下载 [`wowmod-12.0.7-game-dir.zip`](https://github.com/wpch3/wowmod-loadexe/raw/arena/5a3768a5-wowmod-loadexe/wowmod-12.0.7-game-dir.zip)
> 直接解压到 `D:\Midnight Open Beta\_midnight_\`，然后
> `.\wowmod.exe launch --config ".\wowmod.firestorm.json"`（配置在根目录）。
> 手工 x64dbg 解密步骤见 **[../../docs/X64DBG.md](../../docs/X64DBG.md)**。

1. **在 Windows 上启动一次游戏**（`wowmod launch --config wowmod.firestorm.json`），
   然后把 `runtime-dumps/` 目录（含 `.img` 与 `*.candidates.json`）传给我。
   我会据此确认候选是不是「按 FileDataID 打开」的入口，并定稿 `patterns.json`。
2. **或者**：用 x64dbg 在解密后的 `LoadByFileId` / `CustomFileIdHook` 入口断一次，
   给我前 24 字节 + ID 所在寄存器。这条最快。
3. `SET portal` 的私服地址（也别传账号/密码/登录器）。
4. 可选：`.build.info`（Product/Branch/CDN Key）、`Data` 目录树截图、12.0.7 listfile。

## 不需要的 ❌

分卷压缩包、参考模组软件本体、整个 `Data` 目录、任何登录器/反作弊/账号文件。
**请勿上传账号或登录器。**

## 现在能用什么

`wowmod validate` 通过；`plan` 输出 `hook 模式: vfs`：路径型模型文件、AddOns、
`WTF/Config.wtf` / `realmlist.wtf` 内存覆盖、优先级冲突处理全部生效，客户端正常启动。
唯一待定的是 CASC 按 ID 读模型那一条路径，需要上面第 1 或第 2 项来收尾。
