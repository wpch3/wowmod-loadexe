# Windows / PowerShell 快速开始（当前 Arctium 预检路径）

> **先读状态：**本分支包含 89 个纹理和 89 条 FileDataID 映射，并新增了 `arctium-plan` 预检命令。当前尚未实现 Firestorm 12.0.7 的运行时 Arctium hook，也未验证游戏内替换。仓库附带的旧 `wowmod.exe` / `wowmod_hook.dll` 可能不含新命令；不要用旧二进制判断当前源码功能。

## 1. 从当前源码构建 CLI

在 Windows 安装 CMake 与 Visual Studio C++ 工具后，从仓库根目录执行：

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

CLI 通常在 `build\Release\wowmod.exe`。PowerShell 调用当前目录下的程序要写 `.` 前缀：

```powershell
.\build\Release\wowmod.exe --help
```

## 2. 预检 89 个 FileDataID 映射

从仓库根目录执行：

```powershell
.\build\Release\wowmod.exe arctium-plan --config .\examples\12.0.7\wowmod.firestorm.json
```

JSON 输出：

```powershell
.\build\Release\wowmod.exe arctium-plan --config .\examples\12.0.7\wowmod.firestorm.json --json > arctium-plan.json
```

预期：映射 89 个纹理；扫描文件 90 个（`mods\models\README.md` 没有 FileDataID 映射，会被忽略）；重复 ID 0、无效 ID 0。JSON 中 `status` 是 `preflight-only`，`hookInstalled` 是 `false`，这是对当前未安装运行时 hook 的明确标记。

如果在其他目录运行，请使用配置的绝对路径，或通过 `--files-dir DIR` 覆盖 loose-files 根目录。`arctium.filesDir` 和映射文件的相对路径均按配置文件所在目录解析。

## 3. 不要把旧启动命令当成纹理替换测试

本分支中的 `wowmod launch` 仍属于此前的通用注入/VFS 实验流程。即使它能启动客户端、某个线程退出码为 0 或旧 DLL 被加载，也**不代表** FileDataID 资源 hook 已安装或纹理已替换。当前也没有证据证明 Firestorm 有反注入/白名单保护。

继续实现和验证所需资料：

- `runtime-dumps\wow_loader.dll.img`
- `runtime-dumps\wow_loader.dll.candidates.json`
- `runtime-dumps\runtime-report.json`
- `wowmod.log`（完整注入报告）

建议配置 `runtimeScan: true`、`runtimeDelayMs: 15000`、`runtimeAutoInstall: false`。只有当扫描 DLL 实际进入目标进程，内存转储才可能产生；若没有，请保留完整失败报告，不要打开自动 hook。

或者用 x64dbg 提供已解密模块名、目标函数 RVA、入口前后 24–32 字节、FileDataID 所在寄存器/栈槽及宽度、命中/未命中时的返回值语义。这样才能确定 ABI、patch 边界和回滚策略。

不需要重发纹理、客户端路径或安装目录截图；也不需要为这 89 条映射再爬全量游戏数据。公开映射已查齐。若要确认 Firestorm 客户端本地 CASC 归档中存在这些 ID，仍需另外核验该客户端的数据。

当前代码在 Linux 上做过 C++17 编译和核心单元测试，但开发环境没有 Windows 交叉编译器或 Wine，所以**没有 Windows 构建或游戏内验证**。详细状态见 [ARCTIUM-STYLE.md](ARCTIUM-STYLE.md) 和 [示例说明](../examples/12.0.7/README.md)。
