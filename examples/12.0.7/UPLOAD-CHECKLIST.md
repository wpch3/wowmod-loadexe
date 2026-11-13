# 还需要的材料（针对 12.0.7 Firestorm 客户端）

## 已经收到的 ✅

| 文件 | 状态 |
| --- | --- |
| `WoW 12.0.7 - Firestorm.exe` | 73,463,504 字节，SHA-256 `e31066a9fd7f16fc…`；x64 PE32+ |
| `*.7z.001` / `.002` / `.003` | 三个分卷合计 54,823,098 字节，**已验证解压出的 exe 与上面完整 exe 哈希完全一致** |

也就是说：**exe 本体不用再传了**，重复的分卷也可以忽略。我已经在真实 exe 上跑过 `detect`：

```
版本: 12.0.7.68974 (build 68974)     ← 从 StringFileInfo/FileVersion 读的，
架构: x64 | 加载层 DLL: Wow_loader.dll   四元组被私服改成了 1200.7.6897.4，已绕开
支持状态: 已支持（无版本白名单）
```

## 还缺的 ① —— 最关键：`wow_loader.dll`

截图里那个 **38,589 KB / 38 MB 的 `wow_loader.dll`**，仓库里没有。

为什么它是必须的：这个 exe 的**导入表只有一个 DLL、一个函数**（`Wow_loader.dll` ordinal #1）。
也就是说 exe 是个启动壳，真正的游戏代码 / CASC 文件读取 / 「按 FileDataID 打开」逻辑在那个 DLL 里。
我在真实 exe 上做了验证：

- `.text` 有 56 MB 代码，`.rdata` 里能找到 `DBFilesClient`、`FileData ID %d %s`、
  `addons.txt`、`WTF/Config.wtf`、`Data/`、`.build.info`、`wow_loader.dll` 等字符串；
- 但在整个可执行节区里**找不到任何指向这些字符串的 RIP 相对引用**（`xrefCount=0`）——
  字符串与代码不在一个模块里。

**所以**：`wowmod discover` / `adapt` 要对 `wow_loader.dll` 跑，而不是对 exe 跑。
只发 exe 无法确定 CASC 的 FileDataID hook 点；通用 VFS 路径覆盖不受影响。

上传后我会做（都是本地命令，你也可以自己跑）：

```bash
wowmod discover --exe wow_loader.dll --emit hooks/patterns.discovered.json --module Wow_loader.dll
wowmod scan     --exe wow_loader.dll --patterns hooks/patterns.discovered.json
wowmod plan     --config wowmod.firestorm.json
```

`hooks.scanTargets` / `--module` 已支持多模块：特征命中 DLL 时，
加载器会用 `GetModuleHandleW(L"Wow_loader.dll") + rva` 下硬件断点。

## 还缺的 ② —— 小文件（可选但推荐，几 KB 而已）

1. **`.build.info`** —— 真实 `Product` / `Branch` / `Build Key` / `CDN Key`。
   PE 资源已经给出 `12.0.7.68974`，但 `.build.info` 能确认产品线和 CASC 配置。
2. **`WTF/Config.wtf`** —— 我需要里面的 `SET portal "…"` 来生成内存覆盖。
   也可以直接把私服地址告诉我，不必传文件。
3. **`Data` 目录清单**（只要目录树 / 前几十个文件名，**不要传几十 GB 的数据**）——
   截图里 `_midnight_` 下只有 `Cache / Errors / Fonts / Interface / Logs / WTF`，
   没看到 `Data`。加载器现在会向上找两层，但如果数据在别处我需要知道路径。
4. **12.0.7 的 listfile**（`fileId;filePath`）—— 若用 ID 型模型替换，
   需要 ID→路径映射。可以用公开的 wow-listfile 自己筛，或把你手上那份给我。

## 不需要的 ❌

- 分卷压缩包（已验证与完整 exe 一致）；
- 「参考模组软件」/ Arctium App 本体 —— 机制已在代码里实现；
- 整个 `Data` 目录 / CASC 归档；
- 任何账号、密码、登录器、反作弊相关文件。**请勿上传这些**。

## 拿到 DLL 之前能用的部分

`wowmod validate` 通过，`plan` 输出 `hook 模式: vfs`：
路径型模型文件、AddOns、`WTF/Config.wtf` / `realmlist.wtf` 内存覆盖、优先级冲突处理全部生效，
客户端正常启动。唯一未启用的是「按 FileDataID 从 CASC 归档读模型」的那一条路径。
