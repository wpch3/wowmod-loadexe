# wowmod-loadexe

**通用版本（version-agnostic）的 WoW 模组 / 模型替换加载器。**

> 你截图里的 Arctium Mod Launcher 只列了 6 个"支持的游戏客户端"。
> 你的私服版本不在里面 —— 因为这类加载器把**客户端 build 号、内部函数字节特征、目录名**写死在程序里。
> 本项目做相反的事：**程序里没有任何版本号、偏移或特征表**。

```
版本信息    ← 运行时从客户端文件读（.build.info / PE 版本资源），只用于展示与筛选，绝不用于拒绝启动
文件覆盖    ← 拦截稳定的 Win32/ntdll 文件 API，所有 1.x ~ 12.x 客户端都一样
CASC 注入点 ← 外部 patterns.json 数据在真实 exe 上做能力探测；加一条数据 = 适配一个新 build
```

---

## 一眼看懂

| | Arctium 类 launcher | wowmod-loadexe |
|---|---|---|
| 支持版本 | 编译期白名单 | **无白名单，任何 build 都 `supported=true`** |
| 内部函数定位 | 硬编码字节特征 + 版本分支 | 外部 JSON 特征 + 实际 exe 上唯一匹配探测 |
| 找不到 hook 点 | 拒绝启动 / 报不支持 | **自动退化为通用 VFS 覆盖，客户端照常启动** |
| 适配新版本 | 等作者发新版 | 加一条数据，不用重新编译 |
| 私服 portal | 手动改 `Config.wtf` | 内存覆盖，磁盘上的游戏文件不变 |

---

## 三层设计（为什么与版本无关）

### 第 1 层：通用 VFS 覆盖 —— **任何版本都生效**

注入 `wowmod_hook.dll` 后，在 **IAT 层** 替换这些 20 年不变的 API：

`CreateFileW/A` · `NtCreateFile` · `NtOpenFile` · `GetFileAttributesW/A` · `GetFileAttributesExW` · `FindFirstFileW/ExW` · `FindNextFileW` · `FindClose` · `LoadLibraryW/ExW`

客户端请求 `World/Model/.../Dragon.m2` 时，覆盖层把路径改指向模组目录里的真实文件。
**没有改客户端任何一条指令**，所以没有"这个版本偏移变了就崩"的问题。

同时提供：
- 路径 → FileDataID 自动关联（用你自己的 `fileId;filePath` listfile，不内置表）
- 冲突按 `priority` / 加载顺序裁决
- 目录枚举叠加（新增 AddOns 目录也能被看到）
- 内存生成 `WTF/Config.wtf`（私服 portal）与 `realmlist.wtf`，落在 `%TEMP%/wowmod-<pid>/`，**不碰游戏目录**
- 运行时新加载的 DLL 自动补装 hook

### 第 2 层：数据驱动的 FileDataID 适配器 —— **需要时才有**

现代 CASC 客户端按 FileDataID 从归档里读文件，不会为每个模型去调 `CreateFileW`。
要在这一层做替换，需要一个 hook 点（客户端"按 ID 打开"的函数入口）。

本项目用 **CPU 硬件断点 (Dr0) + VEH**：断点命中时读取描述符指定的 ID 寄存器，
若该 ID 有覆盖项，就把 `RAX` 设为模组文件的 ANSI 路径并直接 `ret`，让客户端自己去打开松散文件。

> **不修改客户端任何一个字节的代码**，所以不存在"打补丁打错版本导致崩溃"。

hook 点来自 `hooks/patterns.json`，**在真实 exe 上扫描，只有唯一匹配的条目才会启用**：
- 匹配不上 / 多处匹配 / 架构不符 → 跳过该条，继续别的
- 一条都没选中 → 自动退化为第 1 层（纯 VFS），客户端照常启动
- 想支持你的私服 build：加一条特征数据即可，**不需要改代码、不需要重新编译**

### 第 3 层：能力探测 —— 而不是版本判断

`wowmod detect` 只读文件：`.build.info`、`PE 版本资源`、目录布局（`Data/data` / `*.MPQ`）、`WTF/Config.wtf`。
这些值只进 `ClientInfo`，用于展示和**用户可选的模组过滤**；代码里没有 `if (build == 12340)` 之类的分支。

---

## Windows 上怎么运行（PowerShell 必读）

截图里的 `无法将"wowmod"项识别为 cmdlet` 有两个原因：你下载的那份 ZIP **还是旧的、没有
编译好的 `wowmod.exe`**；且 PowerShell 默认不搜索当前目录，必须写 `.\wowmod.exe`。
**现在分支里已带上预编译的 x64 `wowmod.exe` + `wowmod_hook.dll`** —— 重新下载当前分支
ZIP（或单独下这两个文件放到根目录，两者必须同目录）就能直接跑。
[Release 说明页](https://github.com/wpch3/wowmod-loadexe/releases/tag/windows-x64-d467d73) 有校验和。

```powershell
.\wowmod.exe version
.\wowmod.exe detect   --config "examples\12.0.7\wowmod.firestorm.json"
.\wowmod.exe launch   --config "examples\12.0.7\wowmod.firestorm.json"
```

**如果你已经在 `D:\Midnight Open Beta\_midnight_>` 里下命令**，直接下载
[`wowmod-12.0.7-game-dir.zip`](https://github.com/wpch3/wowmod-loadexe/raw/arena/5a3768a5-wowmod-loadexe/wowmod-12.0.7-game-dir.zip)
解压到游戏目录，然后 `.\wowmod.exe launch --config ".\wowmod.firestorm.json"`（配置在根目录）。

中文乱码修复与 `LoadLibraryW` 注入失败排错见 **[docs/WINDOWS-QUICKSTART.md](docs/WINDOWS-QUICKSTART.md)**；
一步步复制粘贴的命令见仓库根目录 **[RUN.txt](RUN.txt)** 与
**[docs/WINDOWS-QUICKSTART.md](docs/WINDOWS-QUICKSTART.md)**，
x64dbg 手工解密/定位见 **[docs/X64DBG.md](docs/X64DBG.md)**。

## ⚠ 真实客户端是加密壳：静态特征扫描无效

上传的 `wow_loader.dll`（39,514,832 字节）查清了一个决定性事实：

- exe 的 `.text`（53 MB）采样熵 **7.95–8.00**，零字节 0.4%，几乎没有正常 x64 函数序言
  → 磁盘上是**密文/压缩数据**，运行时才由加载层解密；明文游戏字符串只留在 `.rdata`。
- `wow_loader.dll` 的 `.text`（31 MB）是真实代码，但游戏字符串被剥光，
  只剩 `eidolon-generator .../loader.pdb` 和 `.eid`/`.eidsig` 自定义节区。
- 对两个文件跑 `wowmod discover` 都是 `xrefCount=0` —— 磁盘上不存在可引用的明文代码。

**所以**：通用 VFS 层（IAT hook 文件 API）照常可用，但 FileDataID hook 点只能从
**运行时已解密的进程内存**里找。已实现 `hooks.runtimeScan`：

```
注入 → 等 runtimeDelayMs 让壳解密 → VirtualQuery/ReadProcessMemory 转储模块内存
     → 在「文件偏移==RVA」的映像上做 discover → 写出 *.img / *.candidates.json
     → 默认只产出候选，不自动下断点
wowmod discover --exe runtime-dumps/main.exe.img --mapped --emit hooks/patterns.runtime.json
```

详见 [examples/12.0.7/UPLOAD-CHECKLIST.md](examples/12.0.7/UPLOAD-CHECKLIST.md)。
**还差一次 Windows 真机启动**（把 `runtime-dumps/` 发我）或用 x64dbg 断一次入口，
才能把最后那条 hook 点定稿；不是再上传更多文件能解决的。

## 真实客户端：12.0.7 Firestorm（已验证）

仓库 `main` 分支上上传的 `WoW 12.0.7 - Firestorm.exe`（73,463,504 字节）已在本地真实跑过：

```
版本: 12.0.7.68974 (build 68974)   ← 私服把 VS_FIXEDFILEINFO 改成 1200.7.6897.4，
架构: x64 | 加载层 DLL: Wow_loader.dll   加载器改从 StringFileInfo/FileVersion 读取
支持状态: 已支持（无版本白名单）
```

三个分卷（`.7z.001~003`）解压出的 exe 与完整文件 SHA-256 完全一致，不用重复上传。

**关键发现**：这个 exe 是**启动壳** —— 导入表只有 `Wow_loader.dll` 的一个 ordinal。
`wowmod discover` 在 56 MB `.text` 里能找到 `DBFilesClient`、`FileData ID %d %s` 等
明文字符串，但 `xrefCount=0`。DLL 上传后进一步确认：exe 的 `.text` 熵 8.00（密文）、
DLL 的字符串被剥光，**两个文件的磁盘内容都没有可引用的明文代码**。因此不是"再对
DLL 扫一遍"就能解决，而是必须走运行时内存扫描（见上一节）。已具备：

- `hooks.scanTargets` / `--module Wow_loader.dll` 多模块扫描，命中 DLL 时
  用 `GetModuleHandleW(L"Wow_loader.dll") + rva` 下断点；
- `hooks.runtimeScan` + `--mapped`：注入后转储解密内存并自动产出候选；
- 纯 VFS 模式与磁盘是否加密无关，照常启动、路径型覆盖照常生效。

完整清单见 [examples/12.0.7/UPLOAD-CHECKLIST.md](examples/12.0.7/UPLOAD-CHECKLIST.md)，
按真实路径填好的配置见 [examples/12.0.7/wowmod.firestorm.json](examples/12.0.7/wowmod.firestorm.json)。

## WoW 12.0.7 能用吗？能

[`examples/12.0.7/`](examples/12.0.7/README.md) 是这个版本的可直接运行起始包。
`detect` 会显示 `12.0.7 / x64 / casc` 和「已支持（无版本白名单）」，`plan` 里的路径型覆盖立刻生效 —— **不需要改任何代码**。

CASC 客户端「按 FileDataID 读模型」需要一条在**你的 exe** 上唯一匹配的特征。
**这一步不需要把任何文件上传给我** —— 两条命令都在你自己机器上跑：

```bash
# A. 完全没有参考特征：让加载器从你 exe 的字符串引用里找候选 hook 点
wowmod discover --exe "D:/Games/WoW/Wow.exe" --emit hooks/patterns.discovered.json

# B. 有邻近 12.x 的特征：自动放宽成你这个 exe 上唯一匹配的版本
wowmod adapt --exe "D:/Games/WoW/Wow.exe" --pattern "48 89 5C 24 08 ..." \
             --out hooks/patterns.adapted.json --name "wow-12.0.7"

wowmod scan --exe "D:/Games/WoW/Wow.exe" --patterns hooks/patterns.adapted.json
wowmod plan --config wowmod.json     # hook 模式: fileid
```

详见 [docs/ADAPTING.md](docs/ADAPTING.md)。即使不提供特征，加载器也会以通用 VFS 模式正常启动。

> 想让我帮你把特征验证好也行：发 `Wow.exe`（或 `.text` 片段）给我即可。
> 但**不需要上传任何模组软件** —— 模组包只是数据，参考软件的机制已经在代码里实现了。

## 快速开始

### 1. 构建（Linux / macOS 也能构建核心 + CLI + 测试）

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure      # 115 项检查
```

### 2. 生成配置骨架

```bash
./build/wowmod init --dir "D:/Games/MyPrivateServer"
cd "D:/Games/MyPrivateServer"
```

生成的目录：

```
wowmod.json                 配置
mods/example/               模组包（按游戏内路径放文件）
mappings/listfile.txt       fileId;filePath 映射
hooks/patterns.json         hook 特征（数据）
```

### 3. 探测（注意输出：**已支持**，无论什么版本）

```bash
./build/wowmod detect
./build/wowmod validate
./build/wowmod plan          # 干跑：完整覆盖表 + hook 选择，不启动游戏
```

### 4. 启动（Windows）

```bash
wowmod.exe launch --config wowmod.json
```

流程：`CREATE_SUSPENDED` → 注入 `wowmod_hook.dll`（与 `wowmod.exe` 同目录）→ 恢复主线程。

---

## 用你自己的私服版本替换模型（三步）

1. **放文件**：把替换文件按游戏内路径放进模组目录
   ```
   mods/my-model/World/Model/Example/Dragon.m2
   ```
   或写 `wowmod.manifest.json` 直接按 FileDataID 指定：
   ```json
   { "files": [ { "id": 123456, "file": "Dragon.m2" } ] }
   ```

2. **给 listfile**：把该版本的 `fileId;filePath` 表放进 `mappings/`，在 `wowmod.json` 里登记。
   路径覆盖会自动获得 FileDataID（来源：[wowdev/wow-listfile](https://github.com/wowdev/wow-listfile)）。

3. **（仅 CASC 按 ID 读取时需要）加一条特征**：用 `wowmod scan --exe Wow.exe --patterns hooks/patterns.json`
   检查你的特征是否**唯一匹配**；唯一即会被自动选用。详见 [docs/ADAPTING.md](docs/ADAPTING.md)。

`wowmod plan` 会告诉你当前是 `vfs` 还是 `fileid` 模式、为什么，以及最终生效的覆盖表。

---

## 演示（不需要真的装魔兽）

```bash
python3 tools/make_fake_client.py --dir examples/demo/client --version 3.3.5.12340
./build/wowmod plan  --config examples/demo/wowmod.json
./build/wowmod scan  --config examples/demo/wowmod.json
```

`tools/make_fake_client.py` 生成一个合法的 PE32+ 文件 + `.build.info` + `Data` 目录（**不是游戏**），
用来验证版本探测、CASC/MPQ 布局探测、特征扫描、覆盖表与启动计划。

换个版本试试，输出依然是「已支持」：

```bash
python3 tools/make_fake_client.py --dir examples/demo/client --version 12.1.5.70783
./build/wowmod detect --config examples/demo/wowmod.json
```

### Web 控制台（实时联动真实 CLI）

```bash
node web/server.js        # http://localhost:3000
```

左侧输入任意私服版本号 → 后端重新生成合成客户端并调用 `wowmod plan --json`；
启用/禁用模组、改优先级、加特征、导出 `wowmod.json` 都会走同一套 C++ 核心。

---

## 配置速查

```jsonc
{
  "version": 1,
  "client": {
    "exe": "",                 // 空 = 自动发现 wow*.exe（不假设 _retail_ 等目录名）
    "gameDir": ".",
    "portal": "my.private.cn", // 内存覆盖 WTF/Config.wtf 的 SET portal
    "realmlist": "",           // 老客户端：内存覆盖 realmlist.wtf
    "args": ["-console"],
    "clearCache": false
  },
  "mods": [
    {
      "name": "模型替换",
      "path": "mods/my-model",
      "root": "",               // 包内相对游戏根目录的子目录
      "enabled": true,
      "priority": 10,           // 数字越大越优先，冲突按此裁决
      "when": {                 // 可选：让用户限定生效范围（不是加载器白名单！）
        "minBuild": 0, "maxBuild": 0, "builds": [],
        "products": [], "storage": [], "arch": []
      }
    }
  ],
  "mappings": ["mappings/listfile.txt"],
  "rules": [
    // { "match": "World/**/*.m2", "replace": "" }   // replace 为空 = 屏蔽该路径
  ],
  "hooks": {
    "mode": "auto",            // auto | vfs | fileid | off
    "patterns": ["hooks/patterns.json", "hooks/patterns.adapted.json"],  // 可写单个字符串或多个文件
    "scanTargets": ["Wow_loader.dll"],  // 私服壳 exe：连同导入的加载层 DLL 一起扫描
    "allowFallback": true,     // 找不到 hook 点仍以 VFS 启动
    "runtimeScan": true,       // 加密壳：等解密后扫描进程内存，产出候选
    "runtimeDelayMs": 4000,
    "runtimeDump": "runtime-dumps",
    "runtimeModules": ["wow_loader.dll", ""],
    "runtimeAutoInstall": false // 候选未经调试器确认前不自动下断点
  },
  "log": { "file": "wowmod.log", "verbose": false }
}
```

支持 `//`、`/* */` 注释与尾随逗号。所有相对路径相对配置文件所在目录。

---

## CLI

| 命令 | 作用 |
|---|---|
| `wowmod init [--dir DIR]` | 生成示例配置与目录 |
| `wowmod detect [--exe\|--dir] [--json]` | 探测客户端，无版本校验 |
| `wowmod validate [--json]` | 校验配置 / 模组 / 映射 |
| `wowmod plan [--json] [--materialize DIR]` | 干跑：覆盖表 + hook 选择 |
| `wowmod scan --exe FILE [--patterns] [--json]` | 在真实 exe 上报告特征匹配 |
| `wowmod adapt --exe FILE --pattern TEXT [--out]` | 把邻近 build 的特征自动放宽成该 exe 上唯一匹配的特征 |
| `wowmod discover --exe FILE [--anchors] [--emit] [--module]` | 找候选 hook 点（字符串 + 指针表 + RIP 相对引用），`--exe` 也可指向 DLL |
| `wowmod launch [--dry-run]` | Windows 启动并注入 |
| `wowmod version` | 版本 |

`--json` 输出可直接被 Web 控制台 / 脚本消费。

---

## 诚实的边界（请读）

"适配任何版本"指的是**加载器不会因为版本未知而拒绝工作**：它总会启动客户端、总会应用通用 VFS 覆盖。
但有几点必须说清楚：

- **CASC 客户端按 FileDataID 从归档读取的文件**，需要第 2 层的 hook 点；这个点必须来自 `patterns.json` 的一条特征。
  没有特征时这些文件不会被替换，但路径型文件（配置、AddOns、松散文件、MPQ 时代客户端）依然全部生效。
  查特征的方法见 [docs/ADAPTING.md](docs/ADAPTING.md)，`wowmod scan` 会帮你验证唯一性。
- 硬件断点适配器目前支持 **x86 / x64**，ARM64 会退回纯 VFS；每个线程用 Dr0，靠 200ms 轮询给新线程补装，极早期加载的资源可能漏掉。
- `NtQueryDirectoryFile` 未 hook：新增文件的目录枚举走 `FindFirstFile*` 层；**替换**已有文件不受影响。
- 内存生成文件会落到 `%TEMP%/wowmod-<pid>/`（不在游戏目录），其余文件一律只读打开。
- 本项目面向**私服 / 离线 modding**。请勿用于官方服务器 —— 会封号。详见 [docs/LIMITATIONS.md](docs/LIMITATIONS.md)。

---

## 文档

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — 架构与数据流
- [docs/ADAPTING.md](docs/ADAPTING.md) — 为任意私服 build 添加特征（含 12.0.7 步骤）
- [examples/12.0.7/README.md](examples/12.0.7/README.md) — 12.0.7 起始包
- [docs/MODS.md](docs/MODS.md) — 模组包 / 映射 / 优先级
- [docs/BUILD.md](docs/BUILD.md) — Windows 构建、交叉编译验证、CI
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — 限制与风险

MIT License · 见 [LICENSE](LICENSE)
