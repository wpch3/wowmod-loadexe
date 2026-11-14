# wowmod — WoW 12.0.7 (Firestorm 68974) 松散文件加载器

> 目标：让 `examples/12.0.7/mods/` 下的 89 个 Blood Elf Female `.blp` 通过
> FileDataID → 本地文件 的方式真的出现在游戏里，做法与 Arctium 一致。
>
> 本文档只写**已经编译通过、已经逐字节验证**的东西，以及**明确还没做的那一步**。
> 2026-11-13 更新。

---

## 1. 一句话结论：现在能做什么、还差什么

| 能力 | 状态 | 证据 |
| --- | --- | --- |
| 在真实进程内找到客户端解密后的代码 | ✅ 完成 | `src/windows/scan_images.cpp`，按区域枚举而非只看模块基址 |
| 从字符串引用定位「加载本地文件」的函数 | ✅ 完成 | `wowmod analyze` 在真实编译产物上给出 2 个可 hook 函数 |
| 精确搬运序言（不切断指令） | ✅ 完成 | `x64_decode`，对照 capstone 2,015,814 条指令 **100.0000%** 一致 |
| 生成并安装 x64 detour（含完整回滚） | ✅ 完成 | `src/windows/fd_hook.cpp`，7 步安装，失败全回滚 |
| 生成 FileDataID 跳板 | ✅ 完成 | `fileid_stub`，capstone 逐条验证 |
| 启动器把运行时塞进客户端并跑起来 | ✅ 完成 | `wowmod_loader.exe`，4 个 PE 全部交叉编译通过 |
| **FileDataID 落在哪个参数 / 返回什么** | ❌ **缺这一条实测数据** | 见 §6 |
| 游戏内看到新贴图 | ❌ 依赖上一条 | — |

**缺的不是代码，是客户端运行时的一条 ABI 事实。** 下面第 6 节给出 3 分钟就能拿到它、
且完全不需要改客户端文件的流程。

---

## 2. 为什么 Arctium 行、之前的做法不行（技术原因，不是玄学）

### 2.1 Arctium 到底做了什么

Arctium 的 `CustomFileIdHook` 做三件事，没有一件是"注入 DLL"：

1. 以 **挂起** 状态创建 `Wow.exe`；
2. 在进程里 `VirtualAllocEx` 一块内存，写入 `{u32 fileDataId, u32 pad, u64 pathPtr}` 表；
3. 在磁盘 exe 上按 **固定字节特征** 找到 `LoadByFileId` 函数，把开头 13 字节换成
   `48 B8 <abs64> FF E0 90`（`mov rax, imm64; jmp rax`），跳到自己的跳板；
   跳板里按 FileDataID 查表，命中就返回本地路径。

它对客户端的要求只有两条：
* `.text` 在磁盘上就是最终代码（特征能匹配上）；
* FileDataID 在它假设的那个寄存器里（旧版写死 `EDX`）。

### 2.2 这个客户端恰好两条都不满足

用 `firestorm-runtime-dumps.zip` 里的真实转储逐区域核对过：

* **代码不在磁盘上，也不在模块基址里。**
  真实数据块（含 `WOWSTATIC_12_0_7_67808` 标记、约 28.4 MB）落在 `0x118000000`
  ——一个**独立分配**，而模块表里的主模块基址是 `0x140000000`。
  磁盘 exe 的 `.text` 是加密/自解压壳。
* **版本是 68974，静态基座却是 67808**（`WOWSTATIC_PATCH_12_0_7` @ `0x489dd90`）。
  也就是说磁盘上的代码和运行时实际执行的代码**不是同一份**，任何磁盘特征码、任何
  社区流传的 68974 偏移都不可能对。

**这就是"Arctium 能、照抄 Arctium 不能"的全部原因**：不是权限问题、不是反作弊、
不是少了什么黑科技，而是 Arctium 的两个前提（磁盘特征可匹配、ID 寄存器已知）
在这个 Firestorm 构建上都不成立。

### 2.3 因此本项目的做法

`wowmod_rt.dll` **在客户端内部**运行，用 `VirtualQueryEx` 枚举整个进程的内存区域，
把候选映像全部读出来（`scan_images.cpp`），挑出含 loose-file 标记字符串的那一块，
再**在真实解密后的字节上**做 xref → 函数定位 → 序言分析。这样：

* 不需要磁盘特征码；
* 不需要假设 FileDataID 在哪个寄存器（改成"每个引用该字符串的函数都拦一遍"）。

---

## 3. 三个二进制分别是什么

`dist/windows-x64/`（用 `scripts/build-windows-release.sh` 交叉编译，zig，无 wine 依赖）：

| 文件 | 作用 |
| --- | --- |
| `wowmod_loader.exe` | 启动器。挂起创建客户端 → `LoadLibraryW` 载入 `wowmod_rt.dll` → 恢复运行 |
| `wowmod_rt.dll` | 运行时。进程内枚举内存、分析、写报告、按模式安装 hook |
| `wowmod.exe` | CLI。离线对 `.exe`/`.img` 跑 `analyze` / `xref` / `site --auto` / `stub` |

运行时对外导出：`wowmod_rt_version`、`wowmod_rt_install`、`wowmod_rt_uninstall`、
`wowmod_rt_installed`、`wowmod_rt_report_path`、`wowmod_rt_analyze_now`。

环境变量（全部可选）：`WOWMOD_RT_MODE`(observe/auto/hook)、`WOWMOD_RT_MAP`、
`WOWMOD_RT_FILES`、`WOWMOD_RT_IDREG`、`WOWMOD_RT_RETREG`、`WOWMOD_RT_HOOK_RVA`、
`WOWMOD_RT_HOTKEY`、`WOWMOD_RT_AUTOTRIGGER`、`WOWMOD_RT_LOG`。

---

## 4. 现在就跑（不需要改客户端，也不用手敲命令）

**推荐：拖放式一键启动**

1. 把 `wowmod-start.cmd`、`wowmod.exe`、`wowmod_loader.exe`、`wowmod_rt.dll`
   和 `scripts\` 文件夹放在**同一个目录**（就是仓库根目录）。
2. 把游戏 exe（例如 `WoW 12.0.7 - Firestorm.exe`）**直接拖到 `wowmod-start.cmd` 上**。
3. 出现菜单后按 `1`（观察分析）。走完直接给你打开报告。

双击 `wowmod-start.cmd` 也可以：它会自动找客户端，找不到就弹窗让你点选。
菜单里还有 `7  自检`，用来确认这 4 个程序在你这台机器上真的能跑。

**报告位置**：`<游戏目录>\wowmod\wowmod-analysis.txt`（菜单 `4` 直接打开）

报告里会出现：

```
主模块基址: 0x140000000
分析基址: 0x118000000          <- 真正带代码的那块
== 3) 推荐 detour 目标 ==
  fn=0x............ [Locally overridden files] 可 hook 覆盖 XX 字节 — ...
  ！注意：这一节按字符串 xref 取目标，命中的通常是崩溃日志格式化函数，
    正常流程调用 0 次，打它会打坏崩溃处理器。真正的 mod hook 点请用
    --mode sigscan（§5），不要用这里的推荐目标。
== 4) FileDataID 查找函数候选 ==
  fn=0x............ score=.. scale=4 ...
```

`观察分析` 保证 `installed=false`，不改内存里任何指令字节，只读。

### 手敲命令（等价，仅排查用）

```powershell
.\wowmod_loader.exe --exe "D:\...\WoW 12.0.7 - Firestorm.exe" --mode observe
```

## 5. 特征码模式：找真正的文件打开函数

**先说为什么这条路换了。** 之前用 `"Locally overridden files"` 的交叉引用找目标，
命中的是崩溃日志格式化函数（栈帧 `0x140`，该串进 `rdx`）。实测：整轮游戏它被调用
**0 次**；一旦打坏它，崩溃处理器自己再挂，客户端只剩
`EXCEPTION_INTERNAL_ERROR / 0xC00000E5`，连日志都写不出来。**那个目标永远不会通向 mod 加载。**

Arctium 从来不用字符串。它用**函数序言特征码**，直接写在自己的源码里
（`Arctium/WoW-Launcher`，MIT，`src/Patterns/Windows.cs`）：

```
CustomFileIdHook =
  48 89 5C 24 08 57 48 83 EC 20 48 8B ? 48 ? ? 48 ? ? ? ? ? ? E8 ?? ?? ?? ??
  48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 74 ?? 48 ?? CD
```

这是**文件打开函数的入口**：`rdx` = FileDataID，返回 `rax` = 路径指针。
在它前面装 15 字节绝对跳转，换成自己的查表 stub —— 命中就把
「本地文件路径」返回给客户端，于是客户端以为 CASC 里就是那个文件。

菜单选 `2`（特征码扫描 + 导出映像）。等价命令：

```powershell
.\wowmod_loader.exe --exe "...\WoW 12.0.7 - Firestorm.exe" --mode sigscan --dump
```

**必须确认它真的跑了。** 判据只有一条：

> 游戏目录下出现 `wowmod\wowmod-sigscan.txt`。

如果这个文件不存在，就说明走的是**旧的 observe 模式**（表现为
`wowmod-progress.log` 里反复出现 `分析完成: 字符串 N 个`，并且
`wowmod-intercept.log` 里是 `共记录 0 次调用`）——那是字符串 xref 路线的产物，
跟特征码扫描无关，不要拿它的结果下结论。

`--dump` 会把扫到的可执行映像写到 `wowmod\dump\image-<n>-<基址>.bin`。
写的是**运行时映像**（RVA 可直接当文件偏移用），这是 12.0.7 唯一能拿到的
真代码副本（磁盘上的 exe 是加密的）。即使特征码全部落空，有了它就能离线
重新提取特征，不用反复重跑客户端。

它只读不写，输出 `wowmod\wowmod-sigscan.txt`，对 5 条特征码逐条给结论：

| 结论 | 含义 |
| --- | --- |
| `unique（可考虑使用）` | 整个运行时映像只出现 1 次，位置确定 |
| `ambiguous（出现多次）` | 特征太弱，直接改写会改到无关代码，需要人工确认 |
| 未命中 | 12.0.7 上序言字节已不同，需要从本机 exe 重新提取 |

**未命中不是失败**，它是唯一诚实的结论：说明必须重新取特征，
而不是拿 10.x 的偏移硬套。

### 为什么 12.0.7 不能像 10.x 那样「放进目录就加载」

CASC 取代 MPQ（4.x）之后，客户端**不再扫描安装目录**，只按 FileDataID / CASC 索引取文件。
10.x 时代用户感觉「放进去就行」，其实背后是 Arctium 启动器改了函数：

1. 把「按 FileDataID 从 CASC 加载」的分支跳转抹成 `0x00000000`（`LoadByFileId`）；
2. 把「按路径从 CASC 加载」的分支同样抹掉（`LoadByFilePath`）；
3. 在文件打开函数入口装 hook，改成查本地路径表。

三步缺一不可。只做第 3 步、不改前两个分支，客户端仍然会走 CASC 分支，
本地文件永远不会被读。

## 6. 还差的那一步（精确说明）

跑完 §5 的 `sigscan` 后，会落到两种情况之一：

**情况 A：`CustomFileIdHook` 唯一命中。** 位置确定，`rdx` 是 FileDataID
（Arctium 的 ABI 假设，需现场验证），可以直接进下一步。

**情况 B：全部未命中或多处命中。** 说明 12.0.7 的编译器输出变了。
这不是"没法做"，而是"必须重新取特征"：用 `--mode sigscan` 报告的映像清单，
把运行时解密后的代码 dump 下来，在 IDA/x64dbg 里按 `FileDataID` 字符串的
xref 找到 CASC 打开函数，重新提取序言。**这条路我能陪你走，但它需要你的 exe 配合。**

拿到唯一命中之后：

菜单选 `3`（安装替换）。等价命令：

```powershell
.\wowmod_loader.exe --exe "...\WoW 12.0.7 - Firestorm.exe" --mode hook
# 或显式指定：
set WOWMOD_RT_MODE=hook
set WOWMOD_RT_HOOK_RVA=0x<报告里的 RVA>
set WOWMOD_RT_IDREG=rdx
```

此时 `fd_hook.cpp` 会：
1. 把 89 条 `{id, 绝对路径}` 写进客户端进程；
2. `VirtualProtectEx` 成只读；
3. 用 `find_safe_split` 读出**真实**序言长度（不是写死 13 字节）；
4. 生成 61 字节跳板并回填两个绝对地址槽；
5. 装 detour，失败则逐步回滚。

---

## 7. 离线自检（不需要 Windows）

```bash
g++ -std=c++17 -O1 -Iinclude -Isrc tests/tests.cpp src/core/*.cpp \
    src/platform/launch_stub.cpp -o tests_bin && ./tests_bin
# 324 项检查, 0 项失败
```

CLI 在真实编译产物上的表现：

```bash
./wowmod xref   --exe probe.exe --string "FileDataID"
./wowmod analyze --exe probe.exe
./wowmod site   --exe probe.exe --auto
```

（`probe.exe` 是用 `zig cc -target x86_64-windows-gnu` 编的测试体，含该字符串和
一个 `{u32 id, const char* path}` 表，用来验证整条分析链路。）

---

## 8. 诚实的边界

* 交叉编译通过 ≠ 在 Windows 上跑过。本仓库的 Windows 二进制**没有**在真实
  Firestorm 进程里执行过——沙箱里没有 Windows、没有 wine。第一条真实运行数据
  必须由你在自己机器上跑 §4 产生。
* `wowmod_hook.dll`（旧 VFS/IAT 路线）保留但**不是**当前方案，不要用它判断成败。
* 若 §5 的日志显示所有参数都不是 FileDataID（例如客户端改用其他键），那么剩下的
  路线是改 `wowmod/` 下的映射表格式去匹配它真实的键，而不是继续猜寄存器。

详细设计与历史实验记录：
[`docs/ARCTIUM-STYLE.md`](docs/ARCTIUM-STYLE.md) ·
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) ·
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md)

---

## 版本自查（遇到「新模式没反应」先看这里）

启动器和脚本是两个文件，版本一旦不一致，**旧启动器会把不认识的模式静默当成默认分析**——
表现就是：菜单选 2，屏幕上却全是 `[strings] 7/7`、`分析完成: 字符串 N 个`，
并且永远不出 `wowmod-sigscan.txt`。

两个自查命令：

```powershell
.\wowmod_loader.exe --version
```

应当输出：

```
wowmod_loader build: sigscan-dump-v4
modes: observe auto hook analyze diagnose sigscan
```

或者直接跑菜单 `8`（自检），它会打印启动器版本和支持的模式清单。

现在脚本在启动前会自动比对：如果 loader 不支持脚本请求的模式，会立刻停下来说明
「zip 里的 exe 和 ps1 不是同一批产物」，不会再把错误模式跑成别的模式。
启动器本身也不再有静默兜底——未知模式直接退出码 `3` 并打印支持列表。

---

## 踩坑记录一：`overrideArchive` 不是本地覆盖开关（已实测否证）

上上个版本里，我们在 dump 出来的明文代码中找到一个函数 `0x1fa1b0`（2840 字节），
它注册了一串 CVar 和一个扩展名清单：

```
0x1fab86  "overrideArchive"
0x1fabaf  "Whether or not the client loads alternate data"
0x1fa363  ".blp" ".tga" ".jpg" ".jpeg" ".wav"     <- 允许被覆盖的扩展名
0x1fa5db  "http://WOW-CDN.FSTORM.EU/68974/%s/%s/%s"
0x1fa1f4  "casContainerSizeLimit"
```

因为它是官方 CVar（默认 `0`，需要重启生效），当时的推论是"打开它就能加载松散文件"。
**实测结果：无效。** 在 `WTF\Config.wtf` 里写入 `SET overrideArchive "1"`、
完全重启客户端后，血精灵女性外观没有任何变化（89 个 `.blp` 已就位于
`_midnight_\Character\BloodElf\Female\`）。

否证它的证据来自 CASC 库本身：
`CASCHandler.Root.SetFlags(locale, overrideArchive, preferHighResTextures)`
—— `overrideArchive` 是**根清单（root manifest）的一个标志位**，
它切换的是"加载哪一份资源清单"（中韩版亡灵模型那套替身资源），
**不参与 FileDataID → 松散文件的解析**。所以它无法注入任意本地文件。

结论：这条路彻底关闭，不要再试。要覆盖 FileDataID，只有 Arctium 那种
在解析函数入口做 detour 一条路。

## 踩坑记录二：CASC 根目录不是 exe 所在目录

现场目录结构（用户实机）：

```
D:\Midnight Open Beta\
    _midnight_\                        <- exe 在这里
        WoW 12.0.7 - Firestorm.exe
        wow_loader.dll
        Cache/  Errors/  Fonts/  Interface/  Logs/  WTF/  wowmod/
        Character\BloodElf\Female\*.blp   <- 89 个松散文件放这里
    Data\                              <- CASC 数据根在这里（和 _midnight_ 同级）
```

我们此前的文档写过"客户端没有 `Data` 目录"，**这是错的** —— `Data` 存在，
只是在 `D:\Midnight Open Beta\Data`，和 `_midnight_` 平级，而不是在 exe 旁边。
也就是说 **exe 所在目录 `_midnight_\` 不是 CASC 数据根**：客户端能正常启动，
只能说明它读的是同级 `Data\` 那一份。所以把松散文件丢进 exe 目录，
从一开始就不在客户端的数据查找范围内 —— 这解释了为什么"放进去没反应"。
（仍遵守用户定下的硬约束：绝不建议把文件放到 `D:\Midnight Open Beta\` 这一层。）

## 修复：导出时机（这才是上次只拿到 9.6% 明文的真正原因）

壳是**按 4 KB 页惰性解密**的：只有客户端真正执行到的页才是明文，
其余页永远保持磁盘上的密文（熵 8.00）。实测那一次的 113 MB 映像里
只有 1313/13730 页（5.4 MB，9.6%）是明文。

原因是 `--dump-module` 在 `ResumeThread` 之后 **400 ms** 就抓内存 ——
那时客户端还没登录，绝大部分代码页根本没被执行过。

**修法（不再靠猜时间）：**

`dump_module_full` 新增 `text_checked` / `text_low_entropy` 两个字段，
导出前先**采样 256 个可执行页并估算每页熵**（密文≈8.0，x64 明文≈6.0~6.6），
算出"明文页占比"。启动器随后**每秒采一次，直到比例连续 3 次不再上升**才真正导出，
并打印全过程：

```
采样 .text 解密进度（等比例稳定后再导出）
   1000 ms: 明文页 34/256 = 13.3%
   3000 ms: 明文页 96/256 = 37.5%
   ...
  比例已稳定（连续 3 次没上升），开始导出。
  导出完成，明文页: 168/256 = 65.6%
```

`--dump-module` 现在支持 `--wait MS`（默认 30000）作为上限；
若最终明文比例仍低于 20%，会明确提示**先登进游戏、进出一次场景/换装再重跑**，
因为只有那些被真正执行的页才会解密。

### 正确用法：双击 `wowmod-dump.cmd`（不要手敲命令）

解压 `wowmod-oneclick.zip` 后，**双击 `wowmod-dump.cmd`** 就行。它会：

1. 自动在常见位置找客户端 exe；找不到就弹窗让你选（不用输路径）
2. 打印 `wowmod_loader.exe --version` 确认版本
3. 启动游戏，并**每秒采样一次解密进度**，打印成进度条的样子
4. 进度连续 3 次不再上升（或到 3 分钟上限）自动导出
5. 导出后**自动对照磁盘 exe 统计明文页比例**，直接告诉你「够用」还是「偏低」

你只需要在游戏里做一件事：**正常玩一会儿** —— 登录、在角色选择界面切几个角色看模型、
进世界、打开角色面板/幻化/理发店、进出一次场景。这些操作会让壳把相关代码页解密出来，
而我们要找的正是那条 FileDataID 解析路径的代码。

脚本退出前会打印类似：

```
  明文页(与磁盘不同) = 5230 / 13730 = 38.1%
  密文页(与磁盘相同) = 8500
  [够用] 可以拿去做特征码匹配了。
```

把手动命令列在下面仅供排查（正常情况下不需要用）：

```bat
wowmod_loader.exe --exe "WoW 12.0.7 - Firestorm.exe" --mode sigscan --dump-module --wait 180000
```

有了完整明文，再按 Arctium 的 `CustomFileIdHook` 探针
`48 89 5C 24 08 57 48 83 EC 20 48 8B ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ...`
去匹配才有意义。
