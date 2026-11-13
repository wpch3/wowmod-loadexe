# 12.0.7 Firestorm：素材与运行时验证清单

## 已收到并已处理

- 用户提供 Firestorm 安装目录截图，路径为 `D:\Midnight Open Beta\_midnight_`，其中可见 `WoW 12.0.7 - Firestorm.exe` 与 `wow_loader.dll`。不需要重发截图或路径。
- BloodElf Female 替换包已由用户提交到远端 `main`；当前活动分支已从素材提交 `86e058794ff405f96e81f42f6c1efff52a8c6702` 拷入 `mods/models/Character/BloodElf/Female/`。
- 包内有 89 个 `.blp`，共 12,208,284 字节；本地只检查到 BLP2 文件头和尺寸（58 个 256×128、31 个 1024×512）。没有 `.m2`，所以这是纹理替换包。
- 公开 `wowdev/wow-listfile` 分类 CSV（检查提交 `d0404f4db2a8037b6863734fd744bba8570b8bed`）对 89 个相对路径全部精确匹配到 FileDataID。12 个 skin-color 纹理 ID 为 `3500114–3500125`。公开映射不等于 Firestorm CASC 内容存在性或游戏加载验证。

## 当前可执行的检查

源码新增 `wowmod arctium-plan --config examples/12.0.7/wowmod.firestorm.json`：扫描 `arctium.filesDir`，用配置映射表构造确定性的 ID → 本地路径计划。此命令不启动或修改客户端；计划状态为 `preflight-only`，`hookInstalled` 为 `false`。

建议从包含新源码的构建产物运行，而不是假设仓库里附带的旧 `wowmod.exe` 已更新：

```powershell
.\build\Release\wowmod.exe arctium-plan --config .\examples\12.0.7\wowmod.firestorm.json --json > arctium-plan.json
```

## 尚缺的运行时资料

用户此前提供的日志显示尝试过 LoadLibraryW、NtCreateThreadEx、APC 与 SetWindowsHookExW；这些是注入尝试的结果，**不能据此确认注入成功、客户端存在白名单保护或 hook 已工作**。当前分支配置仍将 `runtimeAutoInstall` 设为 `false`，并建议 `runtimeDelayMs` 为 15000。

要在不猜 hook ABI 的前提下继续实现 Arctium 风格运行时补丁，需要一次 Windows 端采集：

- `runtime-dumps/wow_loader.dll.img`
- `runtime-dumps/wow_loader.dll.candidates.json`
- `runtime-dumps/runtime-report.json`
- `wowmod.log`（需保留完整注入报告）

或者用 x64dbg 提供已解密模块名、目标函数 RVA、入口前后 24–32 字节、FileDataID 实际所在寄存器/栈槽及宽度、命中/未命中时的返回值语义。

## 不需要再次提供 / 不需要额外爬取

- 不需要重发替换包、安装目录截图或客户端路径。
- 不需要为这 89 条路径再爬全量游戏数据；公开路径到 ID 已全部匹配。
- 若要证明 Firestorm 12.0.7 的 CASC 归档内确有这些 ID，需要从该客户端本地数据另行核验；目前没有完成这一步。
- 这里无法进行 Windows 构建或游戏内运行：当前开发环境没有 Windows 交叉编译器、Wine，也没有正在运行的 Firestorm 进程。
