# wowmod-loadexe — Arctium 风格加载器开发中

> **当前目标：WoW 12.0.7 Firestorm x64 的 FileDataID 松散文件替换。**
> 当前分支已经包含 Blood Elf Female 纹理包和 89 条公开 FileDataID 映射，并实现了与 Arctium 输入相同思路的独立映射预检命令。**运行时进程 hook、资源覆盖和游戏内验证尚未完成。**

## 当前分支的可确认状态（2026-11-13）

- `examples/12.0.7/mods/models/Character/BloodElf/Female/`：89 个 `.blp`，共 12,208,284 字节；均为 BLP2 头。
- `examples/12.0.7/mappings/listfile.txt`：89/89 路径在公开 `wowdev/wow-listfile` 分类 CSV 中找到精确 FileDataID；皮肤颜色纹理 ID 为 `3500114–3500125`。
- `wowmod arctium-plan`：独立于旧 VFS 的预检路径，按 `arctium.filesDir` 递归枚举本地文件、以 `fileId;filePath` 映射生成排序后的 ID → 绝对文件路径表，并报告重复/无效 ID。
- 该命令**只生成预检结果**：不启动客户端、不注入、不修改客户端进程、不安装 hook。它不能证明 Firestorm 的 CASC 能读取这些本地文件。
- 当前分支根目录的 `wowmod.exe` / `wowmod_hook.dll` 已从本分支源码交叉编译为 Windows x64；尚未在 Windows 或 Firestorm 进程中运行，hook ABI 和游戏内替换仍待验证。
- 不需要安装 CMake 才能采集转储：在 Windows 上双击根目录的 `collect-firestorm-runtime.cmd`，它会启动样例配置、等待扫描并自动打包输出。

**不要把 `wowmod launch` 的进程启动/注入日志等同于纹理替换成功。** 仓库里仍保留此前的通用 VFS / 硬件断点实验代码，但它不是当前 Arctium 风格实现的依据；旧文档里“所有版本可用”“自动退化后模型立刻生效”等说法不作为 Firestorm 12.0.7 的验证结论。

## 运行 Arctium 映射预检

当前分支根目录已附带包含新命令的 x64 Windows 构建。PowerShell 从仓库根目录可直接运行：

```powershell
.\wowmod.exe arctium-plan --config .\examples\12.0.7\wowmod.firestorm.json
```

如需自行改源码再构建，才需要 CMake 和 C++ 工具链。采集 Firestorm 转储则无需输入命令，双击 `collect-firestorm-runtime.cmd` 即可。

预期 89 个纹理全部映射，另有模组目录说明文件不在映射中。用 `--files-dir DIR` 可临时覆盖 `arctium.filesDir`。JSON 的 `status` 为 `preflight-only`、`hookInstalled` 为 `false` 是有意的，不代表 hook 安装失败或成功。

## Arctium 参考与本项目实现边界

本项目参考公开旧版 [Arctium WoW Launcher @ `bd804c7`](https://github.com/redscarf26/arctium-wow-launcher/tree/bd804c7)（其 README 的支持范围至 10.x）：它枚举 `files/`，按路径查 `fileId;filePath`，将 ID 与本地路径指针表放进目标进程，再在客户端内部按 FileDataID 的入口安装 x64 trampoline。旧源码的寄存器、函数签名和补丁点**不是** Firestorm 12.0.7 的证据。

本分支当前只完成了安全的第一段：**文件树 + FileDataID 映射 → 可审计的确定性输入表**。没有照搬旧版硬编码的 `EDX` 假设或 13 字节补丁；必须先拿到真实 Firestorm 运行时目标函数、参数/返回语义和覆盖字节，再实现对应的进程内存写入与回滚。

详细设计及下一步所需证据见 [`docs/ARCTIUM-STYLE.md`](docs/ARCTIUM-STYLE.md)，12.0.7 素材和配置见 [`examples/12.0.7/`](examples/12.0.7/)。

## 测试

当前可移植核心测试可在有 C++17 编译器的环境执行：

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

此次开发环境用 Linux `g++` 编译并运行核心测试（226 项通过），并用 Zig 交叉编译出 Windows x64 PE、检查了架构与导出符号。没有 Wine 或 Firestorm 进程，因此**未在 Windows 实机运行，也未完成游戏内验证**。
