# Windows 快速采集 Firestorm 运行时资料（无需 CMake）

当前分支根目录已附带用本分支源码构建的 x64 `wowmod.exe` 和 `wowmod_hook.dll`，并有一个自动收集脚本。**无需安装 CMake，也不用手动输入构建命令。**

## 只需双击一次

1. 从当前分支下载/更新仓库文件，确认仓库根目录里有 `wowmod.exe`、`wowmod_hook.dll`、`collect-firestorm-runtime.cmd`。
2. 双击根目录的 **`collect-firestorm-runtime.cmd`**。
3. 客户端启动后保持运行至少 20 秒，让运行时扫描完成。如果启动器窗口一直等着，就在等待 20 秒后关闭游戏；脚本会继续收集。
4. 脚本会自动在仓库根目录生成 **`firestorm-runtime-dumps.zip`**。把这个 ZIP 直接拖进当前 Arena 聊天，或点附件按钮上传。

ZIP 会包括本次新生成的 `.img` / `*.candidates.json` / `runtime-report.json`、配置对应的 `wowmod.log` 和启动输出记录。若未生成转储，也会尽量打包日志以便排查。脚本不会开启 `runtimeAutoInstall`，也不会上传整个游戏目录。

样例配置使用已提供的 Firestorm 路径 `D:\Midnight Open Beta\_midnight_\WoW 12.0.7 - Firestorm.exe`，并将输出放在 `examples\12.0.7\runtime-dumps\`。如果你的游戏路径不同，只需先在 `examples\12.0.7\wowmod.firestorm.json` 里改 `client.exe` 和 `client.gameDir`；不需要改运行时映射。

## 没有生成转储时

这通常说明运行时扫描 DLL 没有成功进入目标进程；并不能据此断定客户端有保护机制。仍请上传脚本生成的 ZIP，里面的启动输出和日志能帮助定位。如果出现旧的转储文件，脚本只会打包本次运行后更新时间较新的转储。

保持配置为 `runtimeScan: true`、`runtimeDelayMs: 15000`、`runtimeAutoInstall: false`。**不要把 `runtimeAutoInstall` 改为 `true`。**

## 只有需要自行改源码时才需要构建工具

需要重新编译时才安装 Visual Studio C++ 工具和 CMake，然后在仓库根目录运行：

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

当前附带的 Windows x64 二进制已经交叉编译并检查 PE 架构/导出符号，但没有在 Firestorm Windows 客户端中运行验证；生成转储不等于 hook 成功或纹理替换成功。详细状态见 [ARCTIUM-STYLE.md](ARCTIUM-STYLE.md)。
