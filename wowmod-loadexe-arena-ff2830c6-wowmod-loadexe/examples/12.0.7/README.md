# WoW 12.0.7 Firestorm 示例（Arctium 风格开发中）

## 当前分支已包含什么

- `mods/models/Character/BloodElf/Female/`：已从远端 `main` 的素材提交 `86e058794ff405f96e81f42f6c1efff52a8c6702` 拷入当前工作分支，共 89 个 `.blp`（12,208,284 字节）。这是纹理替换包，不含 `.m2` 几何模型。
- `mappings/listfile.txt`：这 89 个游戏相对路径均已从公开 `wowdev/wow-listfile` 分类 CSV 找到精确 FileDataID，映射数为 89/89。12 个 skin-color 文件对应 `3500114–3500125`。
- `wowmod.firestorm.json`：保留截图中的 Firestorm 安装路径；`arctium.filesDir` 指向这组 loose files。

映射是公开 listfile 的路径到 ID 关系，**不证明这些 ID 在该 Firestorm 客户端的 CASC 归档里存在，也不代表客户端加载器已经替换它们**。

## 运行映射预检

从仓库根目录用包含本次修改的源码构建后运行：

```powershell
.\build\Release\wowmod.exe arctium-plan --config .\examples\12.0.7\wowmod.firestorm.json
```

也可输出 JSON：

```powershell
.\build\Release\wowmod.exe arctium-plan --config .\examples\12.0.7\wowmod.firestorm.json --json > arctium-plan.json
```

预期：89 个 `.blp` 全部映射；扫描数多 1 是因为 `mods/models/README.md` 没有 FileDataID 映射，会被忽略。JSON 明确写着 `status: preflight-only`、`hookInstalled: false`。

## 尚未完成 / 不要误判

- **还没有**将 ID/路径表分配到 WoW 进程，也没有安装 Arctium 风格 hook/trampoline。
- `wowmod arctium-plan` 不启动游戏、不注入 DLL、不改客户端内存；它只验证 loose-file 文件树和映射输入。
- `wowmod launch` 仍走仓库中旧的通用覆盖层流程，不能把它当作 Arctium 12.0.7 纹理替换成功的证明。
- 尚无 Firestorm 12.0.7 Windows 运行时目标函数、寄存器/返回语义和补丁边界证据；没有完成游戏内验证。注入日志本身也不足以证明客户端保护机制。

旧版 Arctium fork 的源码检查表明其做法是“按文件路径映射 FileDataID → 在目标进程保存路径表 → 在客户端 ID 读取函数入口安装 x64 trampoline”；该 fork 的公开支持范围截至 10.x，不能把旧签名或 EDX 假设直接套到 12.0.7。详见 [`docs/ARCTIUM-STYLE.md`](../../docs/ARCTIUM-STYLE.md)。

## 下一步需要什么

不需要再次发送素材、安装目录截图、客户端路径，也不需要为了这 89 条映射再爬全量游戏数据。要继续实现和验证运行时 hook，需要 Windows 运行时输出：

- `runtime-dumps/wow_loader.dll.img`
- `runtime-dumps/wow_loader.dll.candidates.json`
- `runtime-dumps/runtime-report.json`
- `wowmod.log`

配置建议：`runtimeScan: true`、`runtimeDelayMs: 15000`、`runtimeAutoInstall: false`。若扫描 DLL 没有成功进入游戏进程，请同时保留完整注入诊断；不要打开自动 hook。

也可替代为 x64dbg 记录已解密模块名、目标 RVA、入口前后 24–32 字节、FileDataID 所在寄存器/栈槽和宽度，以及返回值的实际含义。当前已交叉编译 Windows x64 二进制，但没有 Wine 或 Firestorm 进程，无法替代 Windows 客户端运行验证。可双击仓库根目录的 `collect-firestorm-runtime.cmd` 自动运行并打包资料。
