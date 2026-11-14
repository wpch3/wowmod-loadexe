# Arctium 风格 FileDataID 加载路径：设计与状态

## 状态边界

当前分支已实现**文件映射预检**，没有实现客户端运行时安装：

| 阶段 | 状态 | 当前实现 |
| --- | --- | --- |
| 读取 `FileDataID;game-relative-path` 映射 | 已完成 | 复用 `MappingTable` |
| 扫描配置的 loose-files 根目录 | 已完成 | `arctium.filesDir` |
| 建立唯一、可审计的 `FileDataID -> 本地完整路径` 表 | 已完成 | `plan_arctium_files()`、`wowmod arctium-plan` |
| 将表分配到 WoW 进程并写路径字符串 | **未实现** | 需要进程内存实现和错误回滚 |
| 在 Firestorm 12.0.7 的 ID 读取函数安装 trampoline | **未实现** | 缺真实运行时入口、参数 ABI、返回语义与覆盖指令证据 |
| 验证 CASC 取档和游戏画面替换 | **未完成** | 需要 Windows 客户端运行验证 |

`arctium-plan` 不会复用/构建通用 VFS，也不会启动、注入或修改目标进程；它只是后续运行时实现的输入准备步骤。

## 参考实现实际做什么

参考源码：[`redscarf26/arctium-wow-launcher` @ `bd804c7`](https://github.com/redscarf26/arctium-wow-launcher/tree/bd804c7)，检查的提交自述支持到 Dragonflight 10.x，不代表适配 12.0.7。

- `src/ModLoader.cs::GetFileMappingData` 递归扫描 `files/`，把文件相对根目录的路径规范化后，在映射表里找 FileDataID；不匹配的文件跳过，重复 ID 只保留先遇到的文件。
- `LoadFileMappings` 在目标进程创建 ID / 路径数据块：每条记录包含 32 位 ID 与 64 位路径指针，路径字符串另存在一个区块。
- `HookClient` 在 `CustomFileIdHook` 特征位置写入 x64 绝对跳转，并生成小段机器码：旧代码按 `EDX` 取 ID，扫描 ID 表，命中时在 `RAX` 返回路径指针；未命中/特殊值按其旧版逻辑返回或回到原始代码。
- 旧实现使用固定特征、固定 13 字节覆盖长度及特定控制流。不能把它的寄存器约定、hook 点、跳转逻辑或游戏版本范围外推到 Firestorm 12.0.7。

因此，本项目当前先做可验证的输入表，而不是猜 `EDX`、复制一段旧机器码并声称已经可用。运行时实现还必须检查所有远程内存 API 的结果、设置正确页保护、刷新指令缓存，并在失败时恢复原始字节/释放资源；旧源码没有证明这些问题对本目标已解决。

## 当前映射预检行为

`arctium.filesDir` 是 loose-files 根目录；每个本地文件的相对路径按大小写不敏感方式查询配置中的映射表。输出包含：

- `fileId`：仅接受非零 32 位 ID；
- `gamePath`：映射中的游戏相对路径；
- `localPath`：本地绝对路径（当前平台原生分隔符）；
- 文件大小、扫描数量、未映射数、ID 冲突数、超范围 ID 数。

映射结果按 FileDataID 排序。若多条本地路径映射到相同 ID，确定性地保留排序靠前的路径并警告；这避免依赖文件系统的枚举顺序，但与旧版 Arctium 的“先枚举到者胜出”不保证顺序一致。README 等未映射文件会被忽略，不会进入表。

示例：

```sh
wowmod arctium-plan --config examples/12.0.7/wowmod.firestorm.json
wowmod arctium-plan --config examples/12.0.7/wowmod.firestorm.json --json
```

## 12.0.7 已核实的素材事实

- 当前分支包含 `examples/12.0.7/mods/models/Character/BloodElf/Female/` 下的 89 个 `.blp`，文件内容来自远端 `origin/main` 的素材提交 `86e058794ff405f96e81f42f6c1efff52a8c6702`；合计 12,208,284 字节。头部检查为 89 个 BLP2（58 个 256×128、31 个 1024×512）。这是纹理替换包，里面没有 `.m2` 几何模型。
- `examples/12.0.7/mappings/listfile.txt` 中 89 个路径与 `wowdev/wow-listfile` 分类 CSV 提供的映射逐一精确匹配（检查时的 listfile 提交 [`d0404f4db2a8037b6863734fd744bba8570b8bed`](https://github.com/wowdev/wow-listfile/tree/d0404f4db2a8037b6863734fd744bba8570b8bed)）。12 个 `bloodelffemale_hd_skin_color_*.blp` 对应 `3500114–3500125`。
- 这是**公开路径映射**，不是 Firestorm 客户端 CASC 归档存在性证明，更不是游戏内替换成功证据。建立这 89 条映射不需要用户再次发送素材，也不需要再爬全量游戏数据。

## 运行时实现的必要证据

Firestorm 客户端磁盘上的 exe 是加载壳；现有静态签名不能证明 12.0.7 运行时的 `LoadByFileId` / `CustomFileIdHook` 地址或 ABI。用户此前的注入日志只记录了 LoadLibrary/NT 线程/APC/Windows hook 的尝试结果，不能据此判定保护机制，也不能证明 DLL 已在目标进程运行。

下一步需要 Windows 真机运行采集以下文件：

- `runtime-dumps/wow_loader.dll.img`
- `runtime-dumps/wow_loader.dll.candidates.json`
- `runtime-dumps/runtime-report.json`
- `wowmod.log`

建议配置 `runtimeScan: true`、`runtimeDelayMs: 15000`、`runtimeAutoInstall: false`。若这次注入未能让扫描 DLL 在目标进程中运行，请提供日志中完整的注入报告；不要因此打开自动 hook，也不要推断是反作弊/白名单。

替代方式是用 x64dbg 在已解密客户端里记录：模块名、目标函数 RVA、入口前后 24–32 字节、ID 实际在哪个寄存器/栈槽及宽度、函数返回值在命中与未命中时分别代表什么。只有这些证据足以确定 ABI、补丁边界和失败回退后，才能接入受控的 Arctium trampoline。

**不需要**重新上传 `.blp`、安装目录截图或客户端路径；这些都已收到/已检查。公开 listfile 映射已查齐。仍缺的是运行时 hook 证据和 Windows 运行验证。
