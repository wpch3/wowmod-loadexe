# 构建

> 仓库附带的 x64 `wowmod.exe` / `wowmod_hook.dll` 是此前版本的预编译文件，可能不包含本分支的 `arctium-plan`。
> 请按本页从当前源码重新构建。即使编译成功，Firestorm 12.0.7 的 Arctium 运行时 hook 仍未实现/验证；见 [ARCTIUM-STYLE.md](ARCTIUM-STYLE.md)。

## 依赖

- CMake ≥ 3.16、C++17 编译器
- 无第三方库（JSON / PE 解析 / 特征扫描 / 测试全部自实现）
- Windows 目标只需 Windows SDK（系统自带 `windows.h` / `winternl.h`）

## Linux / macOS（核心 + CLI + 测试）

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/wowmod --help
./build/wowmod arctium-plan --config examples/12.0.7/wowmod.firestorm.json
```

这个平台可编译、运行 Arctium 映射预检和核心单元测试。它不能对 Firestorm 客户端做 Windows 进程内 hook 或游戏内验证。

## Windows 构建（仅说明可编译产物，不代表运行时替换已验证）

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

产物：

```
build/Release/wowmod.exe
build/Release/wowmod_hook.dll
```

用构建目录中的 CLI 运行预检（PowerShell 从仓库根目录执行）：

```powershell
.\build\Release\wowmod.exe arctium-plan --config .\examples\12.0.7\wowmod.firestorm.json
```

不要把旧 `wowmod launch` 当成 12.0.7 Arctium 资源替换测试；当前 runtime hook 尚未实现/验证。

MinGW-w64 也可以：`cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release`。
32 位客户端请用 32 位工具链构建（`launch` 会检查位数并给出提示，这不是版本限制）。

## 在 Linux 上验证 Windows 代码（无需 Windows 机器）

仓库提供 `scripts/verify-windows.sh`，用 [zig](https://ziglang.org/) 的 `zig c++` 交叉编译器
把**所有** Windows 源文件编译并链接成真正的 PE：

```bash
python3 -m pip install ziglang
./scripts/verify-windows.sh
```

它会：
1. 用 `-target x86_64-windows-gnu` 编译 `src/core/*.cpp`、Windows 源和 CLI
2. 链接 `wowmod_hook.dll` 和 `wowmod.exe`
3. 校验 PE 头（MZ / PE / machine=0x8664）与导出符号 `wowmod_version` 等

这一步能抓到 MSVC/MinGW 头文件差异、类型不匹配、缺 include 等问题。

## CI

`.github/workflows/ci.yml` 里有两个 job：

- **ubuntu**: GCC 构建核心、运行单元测试及演示命令，并交叉编译校验 Windows 源码
- **windows**: MSVC 构建 `wowmod.exe` + `wowmod_hook.dll`，上传为 artifact

## 生成演示客户端

```bash
python3 tools/make_fake_client.py --dir examples/demo/client --version 12.1.5.70783
```

生成的 `client/` 是**生成物**（已在 `.gitignore` 里）。Web 控制台 `node web/server.js`
在启动时会自动补齐它。

## 目录说明

```
include/wowmod/     公共头文件（可移植核心）
src/core/           可移植核心实现
src/cli/            CLI 入口
src/platform/       平台无关的 launch 接口 + 非 Windows 占位实现
src/windows/        注入 DLL 与 Windows 启动器
tests/              零依赖单元测试
examples/demo/      可运行的演示（合成客户端由脚本生成）
web/                Web 控制台（零依赖 Node HTTP 服务）
tools/              演示客户端生成脚本
scripts/            构建 / 校验脚本
docs/               文档
```
