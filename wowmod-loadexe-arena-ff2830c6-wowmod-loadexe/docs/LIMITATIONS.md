# 当前限制与使用边界

## 12.0.7 Firestorm 当前状态

- 已集成 BloodElf Female 89 个 `.blp`，并从公开 `wowdev/wow-listfile` 分类 CSV 得到 89/89 路径到 FileDataID 映射。
- `wowmod arctium-plan` 能按 `arctium.filesDir` 构造可检查的 ID → 本地路径预检表。
- **没有**把表分配进客户端进程，**没有**在 Firestorm 12.0.7 安装 Arctium 风格 hook，**没有**验证 CASC 归档或游戏画面替换。
- `detect` JSON 中保留的 `supported` 字段仅为旧版兼容字段，表示“没有按 build 白名单拒绝”；它不是资源 hook 能力结果。新字段 `supportStatus: not-verified`、`capabilitiesVerified: false` 才明确表达当前尚未验证。
- 仓库旧 VFS / IAT / 硬件断点代码仍存在，但当前 Firestorm 目标没有被证明可通过这条路线替换 CASC 纹理；不要把旧 `launch` 成功、线程退出码为 0 或本地 DLL 预检通过当成游戏内生效。

## Arctium 风格运行时仍需实现

参考旧版 Arctium 的流程包含 ID 映射表、路径字符串块、客户端按 FileDataID 的入口识别和 x64 trampoline。公开参考 fork 的自述支持范围至 10.x；它不足以证明 12.0.7 使用同一函数、寄存器、返回语义或覆盖长度。

在接入运行时之前必须得到目标客户端的真实证据：模块名、函数 RVA、入口字节及完整指令边界、ID 参数所在寄存器/栈槽和位宽、命中与未命中时的返回含义。还必须实现远程内存写入错误检查、页保护变更、指令缓存刷新、并发/线程安全和失败回滚。

**不要开启** `runtimeAutoInstall`：当前 `mem_scan.cpp` 的实验路径会把候选当作 `rdx`，且本目标 ABI 未确认。唯一特征匹配或候选唯一都不构成 ABI 证明。

## 12.0.7 的验证缺口

用户此前提供的日志包含 LoadLibraryW / NtCreateThreadEx 线程退出码 0 但模块表未见 DLL、APC 等待 3 秒未进入 alertable wait、SetWindowsHookExW 错误 87 和程序报告终止客户端。它们只描述当次注入尝试，不能证明 DLL 已在游戏进程初始化，也不能证明反注入/白名单保护。当前源码在 `keepClientOnInjectFailure=true` 时应恢复进程；与用户日志不符时还需核对实际 exe/config。

下一步需要 Windows 真机收集：

- `runtime-dumps/wow_loader.dll.img`
- `runtime-dumps/wow_loader.dll.candidates.json`
- `runtime-dumps/runtime-report.json`
- `wowmod.log`（完整注入报告）

建议 `runtimeScan: true`、`runtimeDelayMs: 15000`、`runtimeAutoInstall: false`。若扫描 DLL 未进入目标进程，则转储不会产生；也可用 x64dbg 直接记录上述函数/ABI 信息。

公开 listfile 已将 89 个文件路径全部映射到 ID，因此**不需要重新上传素材、截图或路径，也不需要再爬这 89 个路径**。若要证明 ID 存在于 Firestorm 12.0.7 本地 CASC 归档，则需单独使用该客户端的本地数据核验；目前尚未完成。

## 环境限制

本次开发环境是 Linux。可移植 C++17 核心测试已通过，且已用 Zig 交叉编译 Windows x64 PE 并检查架构/导出符号；没有 Wine 或 Firestorm 进程，所以未能在 Windows 客户端中运行、验证进程注入或游戏内替换。根目录的 `collect-firestorm-runtime.cmd` 可由用户双击运行并自动打包运行时资料。完整状态见 [`ARCTIUM-STYLE.md`](ARCTIUM-STYLE.md)。

## 合法与道德边界

本项目只面向有权修改/调试的私服、离线 modding 与学习研究。不得将其用于绕过未获授权的客户端保护或官方服务规则；游戏资源版权归原权利人所有。本项目与 Blizzard / Arctium 无隶属关系。
