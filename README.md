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
wowmod_loader build: sigscan-dump-v11
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

---

## 定论：FileDataID 解析函数已定位（build 68974）

用第二次导出的 108 MB 映像（明文 3064/13730 页 = 22.3%，是第一次 9.6% 的两倍多）
把 Arctium 的 `CustomFileIdHook` 特征码**完整 43 字节**跑了一遍：

```
48 89 5C 24 08 57 48 83 EC 20 48 8B ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? E8
?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 74 ?? 48 ?? CD
```

全 113 MB 映像 **只命中一处**：RVA `0x33e06a0`（基址 0x140000000 → VA `0x1433e06a0`），
且位于已解密的明文页。反汇编确认它的语义**就是** Arctium 描述的那个函数：

```asm
1433e06a0: 48 89 5c 24 08        mov  [rsp+8], rbx          ; 序言，与特征码一致
1433e06a5: 57                    push rdi
1433e06a6: 48 83 ec 20           sub  rsp, 0x20
1433e06aa: 48 8b f9              mov  rdi, rcx              ; 参1 = 容器对象
1433e06ad: 48 63 da              movsxd rbx, edx            ; ★ edx = FileDataID
1433e06b0: 48 8d 0d 51 c2 fc 00  lea  rcx, [rip+0xfcc251]   ; 获取锁
1433e06b7: e8 54 5c ee fc        call 0x1402c6310
1433e06bc: 48 8b 97 30 01 00 00  mov  rdx, [rdi+0x130]       ; 哈希桶数组
1433e06c3: 48 85 d2              test rdx, rdx
1433e06c6: 74 7c                 je   0x1433e0744           ; 空 → 返回 0
1433e06c8: 48 b8 cd 8c 55 ed ...  movabs rax, 0xff51afd7ed558ccd   ; murmur 混合
1433e06d2: 48 b9 53 ec 85 1a ...  movabs rcx, 0xc4ceb9fe1a85ec53
1433e06dc: 4c 8b c3              mov  r8, rbx
1433e06df: 49 c1 e8 21           shr  r8, 0x21
1433e06e3: 4c 33 c3              xor  r8, rbx
1433e06e6: 4c 0f af c0           imul r8, rax
1433e06ea: ...                   （第二轮混合）
1433e0702: 48 8b 87 28 01 00 00  mov  rax, [rdi+0x128]       ; 桶掩码 = 容量-1
1433e070f: 48 8b 04 ca           mov  rax, [rdx+rcx*8]      ; 取桶头
1433e0720: 39 58 08              cmp  [rax+8], ebx          ; ★ 比较 FileDataID
1433e0725: 48 8b 00              mov  rax, [rax]            ; 链式 next
1433e0730: 48 8b 3a              mov  rdi, [rdx]
1433e0738: 48 8b 7f 10           mov  rdi, [rdi+0x10]
1433e073c: 39 9f 04 01 00 00     cmp  [rdi+0x104], ebx      ; ★ 再校验一次 ID
1433e0744: 33 ff                 xor  edi, edi               ; 未命中 → 0
1433e0752: 48 8b 5c 24 30        mov  rbx, [rsp+0x30]
1433e0757: 48 8b c7              mov  rax, rdi              ; ★ 返回查到的对象指针
1433e075a: 48 83 c4 20           add  rsp, 0x20
1433e075e: 5f                    pop  rdi
1433e075f: c3                    ret
```

**这就是一个用 `edx` 当键、在哈希表里查 FileDataID 的函数**：
`Hash(FileDataID) → 桶 → 链表按 [node+8] 比较 → 返回 [node] 关联对象（+0x10 再校验 +0x104）`。
与 Arctium 的 `rdx = FileDataID` 约定完全一致。

### 调用方交叉验证

该函数有 6 个 `call` 调用点（`0x33d4959` / `0x33d688d` / `0x33d69f6` / `0x33d6b92`
/ `0x33d7986` / `0x33d97cb`），**全部落在同一片已解密区域**。第一个调用点：

```asm
1433d4920: 40 53                push rbx
1433d4922: 48 83 ec 20          sub  rsp, 0x20
1433d4926: 8b d9                mov  ebx, ecx          ; 参1 = ID
1433d4928: 85 c9                test ecx, ecx
1433d492a: 75 08                jne  ...               ; ID == 0 → 直接返回 false
1433d4934: 8b 0d 4e 23 fd 00     mov  ecx, [rip+...]
1433d493a: 65 48 8b 04 25 58 00 00 00  mov rax, qword ptr gs:[0x58]   ; TEB
1433d4953: c6 04 02 01          mov  byte ptr [rdx+rax], 1     ; 标记「正在加载」
1433d4957: 8b d3                mov  edx, ebx          ; ★ edx = ID
1433d4959: e8 42 bd 00 00       call 0x1433e06a0       ; ← 就是它
1433d495e: 48 85 c0             test rax, rax
1433d4961: 74 08                je   0x1433d496b
1433d4963: b0 01                mov  al, 1             ; 命中 → 返回 true
1433d496b: 8b cb                mov  ecx, ebx
1433d496d: e8 ee 57 00 00       call 0x1433da160       ; 未命中 → 另一条加载路径
```

`ID == 0` 提前返回、`edx` 传参、命中返回 true 否则 fallback 到另一个加载函数 ——
这与 Arctium `LoadByFileId` 的行为一致。

### 所以现在缺的只有一件事

目标地址有了，剩下的就是**安装 hook 本身**：

1. 在 `0x33e06a0` 处写 13 字节绝对跳转 `48 B8 <stub> FF E0 90 90 90`（Arctium 布局）
   —— 注意：这 13 字节正好覆盖 `mov/push/sub`，而特征码是从函数第一条就开始的，
   所以跳板必须完整复制这 13 字节并在 stub 里执行完再跳回 `0x33e06ad`。
2. stub 里比对 `edx` 与我们的表（`{u32 fileId, u64 pathPtr}` ×12 字节 + NUL 连接的小写路径）；
   命中就返回我们自己的路径指针，未命中就走 trampoline 回原函数。
3. 写入前 `VirtualProtectEx` 改成 RW，写完改回 `0x02`（只读执行）。

**但 0x33e06a0 是每次启动都变的（模块基址随机化）**，所以不能写死 ——
`--mode hook` 必须先用特征码现找。这次 `sigscan` 之所以报 0 命中，
原因已查明并修复：扫描在启动后 47 ms 就跑了，那时只有 11.9% 解密（见下节）。

---

## 复查：`sigscan` 独立确认了静态分析的结论（v5 实机）

第二次 `sigscan` 的运行结果印证了上面的反汇编结论，且是**独立验证**：

```
[CustomFileIdHook]  匹配 0x00000001433e06a0   映像 0x00000001433da000
[CustomFileIdHook]  匹配 0x0000000006f206a0   映像 0x0000000003b40000
```

两处的**相对映像 RVA 完全相同**：

```
0x1433e06a0 - 0x140000000 = 0x33e06a0
0x06f206a0  - 0x03b40000  = 0x33e06a0
```

也就是说"命中 2 次"**不是特征太弱**，而是同一份代码被映射了两个视图
（一个 `MEM_IMAGE` 模块映像 + 一个壳创建的文件映射视图）。所以 v6 起报告里
会打印每处命中的「相对映像 RVA」，两处同 RVA 即可认定为同一目标。

### 环境证据：这两个函数属于引擎的 CAS 模块

`0x33d7bd1` 处的 `lea r8,[rip+0x1eb928]` 指向的字符串是：

```
d:\BuildServer2\Builder\checkouts\0\Engine\Source\CAS\CAS.cpp
```

这是客户端自己的源码路径，出现在 `LoadByFilePathAlternate` 命中点所在函数里；
而我们定位的 `0x33e06a0` / `0x33e0760` 两个哈希查找函数就在它调用的目标位置。
所以可以确定：**Arctium 改的就是引擎 CAS 模块的文件查找函数**，不是别的东西。

### `LoadByFilePathAlternate` 揭示的"客户端自带的路径覆盖路径"

这条特征码在本次扫描里 **unique 命中**（RVA `0x33d7b58`），反汇编如下（节选）：

```asm
1433d7b52: 4c 8b f8              mov   r15, rax
1433d7b55: 40 f6 c6 01           test  sil, 1
1433d7b59: 0f 84 c0 00 00 00     je    0x1433d7c1f      ; ← Arctium 改写的 4 字节
1433d7b5f: 48 8b 0d 6a ff fc 00  mov   rcx, [rip+0xfcff6a]   ; ★ 全局指针
1433d7b6e: 48 85 c9              test  rcx, rcx
1433d7b71: 0f 84 a8 00 00 00     je    0x1433d7c1f      ; 全局为空 → 整段跳过
1433d7b82: e8 d9 8b 00 00        call  0x1433e0760      ; ★ 第二个查表函数
1433d7b87: 48 85 c0              test  rax, rax
1433d7b8a: 0f 84 8f 00 00 00     je    0x1433d7c1f
```

那个全局指针地址是 `VA 0x1443a7ad0`（RVA `0x43a7ad0`，位于 `.data`），
**在我们导出时的值是 `00 00 00 00 00 00 00 00`** —— 空。

这条路径的含义是：客户端**确实自带一条按路径覆盖的加载分支**，但它被
`test sil,1` 和「全局指针非空」两个条件守着；而那个全局在正常启动时是空的，
所以永远走不到。Arctium 的做法是把 `je`（`0F 84`）改成无条件跳过检查
（`NoJump = 00 00 00 00` 正好把 4 字节相对位移清零），强制走进这条分支。

这解释了为什么"把文件丢进目录"从来不起作用：不是文件放错，是这条分支的
入口条件从未成立。也再次说明 `overrideArchive` 那条路与此无关。

### 两个查表函数的区别（v6 起自动判别）

| 函数 | 键宽 | 比较指令 | 用途推断 |
|---|---|---|---|
| `0x33e06a0` | 32 位（`edx`） | `cmp dword [rax+8], ebx` | FileDataID → 资源项 |
| `0x33e0760` | 64 位（`rdx`） | `cmp qword [rax+8], rbx` | 路径哈希 → 资源项 |

两者都用同一套 murmur 混合常数 `0xff51afd7ed558ccd` / `0xc4ceb9fe1a85ec53`，
且共用同一个桶掩码字段（`[this+0x108]` vs `[this+0x128]`）。
路径那条会把 `[rax+0x114]` 这个 u32 写回出参 —— 很可能是 FileDataID 反查。

### v6 新增：语义判别，不再靠人工看地址

`sigscan` 现在对每个 `CustomFileIdHook` 候选做三项结构检查并打分（满分 8）：

| 检查 | 分值 | 指令 |
|---|---|---|
| 键来自 `edx` | 2 | `48 63 DA` = `movsxd rbx, edx` |
| murmur 魔数 | 3 | `ff51afd7ed558ccd` 或 `c4ceb9fe1a85ec53` |
| 按 32 位 id 比较 | 3 | `39 58 08` = `cmp [rax+8], ebx` |

用真实 dump（28.4% 明文）回放，**只有 `0x33e06a0` 拿到 8/8**，
其余 5 处序言巧合全部落选。报告里会直接标 `[目标]`。

---

## 旁路记录（`--mode probe`）：先拿证据，再谈替换

### 为什么不能直接替换返回值

我们已经确证 `0x33e06a0` 是 CAS.cpp 里 `edx = FileDataID` 的哈希查找函数，
Arctium 就是在这里装跳板。但**它的返回值那个对象 `+0x10` 处是什么结构，我们没有证据**。
直接把它换成我们自己的指针 = 拿一个未知对象当资源用，客户端必崩。
这跟"猜特征码偏移"是同一类错误，不能重复。

所以第一版 hook 只做一件事：

```
记下 edx → 原样执行被搬走的指令 → 跳回原函数
```

不写返回寄存器、不改控制流、不改任何寄存器结果。最坏情况是日志不准，
**不会影响客户端加载资源**。退出时把原始字节写回。

### 跳板结构（84 字节，手写机器码）

```
push rax / rcx / rdx / r10 / r11 / pushfq      ; 保存现场（r10/r11 被跳板占用）
mov  r10, <环形缓冲 VA>
mov  r11d, edx                                 ; 只读，不改
total++
槽位 = r10 + 0x18 + head*16
[槽位+0]  = id
[槽位+12] = total                              ; seq，宿主靠它判断新鲜度
head = (head + 1) & (capacity - 1)
popfq / pop r11 / r10 / rdx / rcx / rax        ; 恢复现场
jmp  qword ptr [rip+0] <trampoline>            ; 执行被搬走的原始指令
```

几个刻意的设计：

- **不写 rax** —— 这是它和 `fileid_stub`（替换模式）的根本区别
- **保存 r10/r11** —— 跳板自己要用它们，而"被搬走的原始指令"可能也在用
- **不碰 rsp 以外的栈操作** —— 只有 push/pop，成对出现
- **不调任何 API** —— 在客户端主线程里调文件/堆 API 会死锁，所以只写内存

环形缓冲布局（4096 槽 × 16 字节）：

```
+0x00 u32 magic 'WMPR'   +0x04 u32 capacity
+0x08 u32 head           +0x0C u32 total
+0x10 u32 dropped        +0x18 槽位数组
```

宿主每 2 秒按 `total` 的增量读一次新增记录并写盘，所以读得慢只会丢记录
（有 `dropped` 可查），不会拖慢客户端。

### 怎么用

**双击 `wowmod-probe.cmd`**，然后在游戏里正常玩一会儿：
切角色、进世界、开角色面板/幻化/理发店、进出场景。最长监控 5 分钟，结束后自动卸载。

输出 `wowmod\wowmod-probe.txt`，内容是客户端真实请求的 FileDataID 序列：

```
seq=1  id=1181621  (0x00120735)
seq=2  id=1181622  (0x00120736)
...

累计调用次数: 8421
  id=1234567    x312
  ...
```

### 拿到这份数据之后

我们才知道三件事，而这三件事目前都是未知：

1. 血精灵女性那 89 个 `.blp` 对应的 **FileDataID 是多少**（客户端自己会请求它们）
2. 客户端是按 id 查还是按路径查（如果主要走 `0x33e0760` 那条 64 位键的表，
   那 `CustomFileIdHook` 就不是唯一入口）
3. 我们要替换的返回值该长什么样

有了 1，就能把 id 和本地文件对上；有了 2 和 3，才能安全地写替换逻辑。

### 测试

新增 113 项检查（合计 **536 项，0 失败**），覆盖：

- 跳板每一段都能被 `x64::decode` 完整解码（错一位就是崩客户端）
- 结尾必须是 `FF 25 00000000` + 8 字节绝对地址
- push/pop 必须配平，且至少保存 5 个寄存器 + rflags
- **必须不出现从表里取路径的指令**（那是替换模式才做的事）
- 必须保存 r10 和 r11
- 非 2 的幂容量 / rsp / 越界寄存器必须被拒绝

---

## 探针崩了：原因是「改代码时没让别人停手」

第一次跑 `--mode probe` 时客户端在游戏内崩了：

```
EXCEPTION_INTERNAL_ERROR
0xC00000E5 (EXCEPTION_INTERNAL_ERROR) at 00007ffdf976741ca
0xC0000005 (ACCESS_VIOLATION) ...
```

`0xC00000E5` 是 **STATUS_ILLEGAL_INSTRUCTION**。跳板本身的机器码没错
（84 字节逐条反汇编 + 548 项测试都验过），错在**安装方式**。

### 三个真实缺陷（都已修）

**1）14 字节跳转不是原子写**（这是崩溃的直接原因）

```
48 B8 <imm64> FF E0   ; 14 字节绝对跳转
```

客户端是多线程的。`WriteProcessMemory` 把这 14 字节分成几次写进去的过程中，
只要有别的线程正好执行到函数开头，就会读到一条**混合态**指令 —— 直接非法指令。
`FlushInstructionCache` 放得再对，也救不了这个窗口。

修法：写入前用 `SuspendThread` 挂起目标进程所有其它线程，写完刷缓存、回读校验，
再 `ResumeThread`。挂起时间只有几毫秒，不会触发客户端看门狗。

**2）`write_remote_paged` 在跨页时提前恢复了页保护**

14 字节跳转如果跨页，早期实现是「写完第一页 → 立刻恢复第一页保护 → 写第二页」，
而且 `FlushInstructionCache` 在整个循环之后才调用。也就是说第一页的写入
是在它**已经不可写之后**才被刷进指令缓存；`PAGE_EXECUTE_WRITECOPY` 的写时复制
语义更麻烦，恢复保护后私有副本可能被丢弃。结果客户端执行的是一段被改了一半的函数头。

修法：所有页写完 → 刷新指令缓存 → **最后**逐页恢复原保护。

**3）卸载同样有撕裂问题**

`remove_detour` 原来直接写回原始字节，没挂起线程。客户端还在跑的时候卸载，
同样会撞上混合态。已改成与安装一致的「冻结 → 写 → 刷缓存 → 回读校验 → 解冻」。

### 新增：崩溃现场判定（这才是以后不再瞎改的关键）

崩了之后，我们**无法证明**崩的那条指令是不是我们改的 —— 那只是推断。
所以新增 `crash_evidence`：

- 在 `%LOCALAPPDATA%\CrashDumps`、`WER\ReportArchive`、客户端 `Errors/` `Logs/` 里
  找最新的 `c00000e5` 相关转储
- 不依赖 `dbghelp.dll`，直接读 minidump 的 `EXCEPTION_STREAM`(6)，
  取出 `ExceptionCode` 与 `ExceptionAddress`
- 把 RIP 和我们改过的地址区间做比较，直接给结论：

| 判定 | 含义 |
|---|---|
| 落在 hook 区间内 | 探针写入有问题（原子性） |
| 落在跳板/trampoline 内 | 跳板机器码有 bug |
| 都不在 | **与探针无关，问题在别处，不要再改 hook 代码** |

第三行是重点。没有这个判定，下次崩了又会去改 hook，而真正的原因可能在别处。

minidump 的偏移约定用一份按真实形状构造的假转储做了验证
（`0xC00000E5` + RIP `0x7ffdf976741ca`，就是用户截图里那两个值），
固化为单元测试。

### 现在的状态

- 总计 **548 项检查，0 失败**
- 安装/卸载都有回读校验：写进去的字节必须真的在那儿，不一致当场报错
- 探针模式不再每秒跨进程采样 256 页（那会明显拖慢刚启动的客户端）

### 下一步

先跑一次 `wowmod-probe.cmd`。如果还崩，**先看输出的「崩溃现场判定」那一节**：

- 如果判定是「不在我们改的字节里」→ 说明 `0x33e06a0` 被别的线程/检查改过，
  或者那条路径本身在游戏内有别的副作用，**不要再动 hook 代码**
- 如果判定是「落在跳板内」→ 跳板有 bug，我们拿着 RIP 精确对齐反汇编再修

这次至少不会再有"崩了但不知道崩在哪"的情况。

---

## 第二次崩溃：确定性，且 RIP 完全相同

第二次跑探针，日志显示一切正常：

```
[成功] 目标 0x0000000006f306a0（语义分 8/8）
环形缓冲 @00000000009e0000（4096 槽 x 16 字节）
hook 点可搬运 16 字节完整指令
旁路跳板生成完成: 84 字节
detour 已安装: 0000000006f306a0 -> 0000000017bb0000
```

但进游戏后立刻崩，**RIP 与第一次一字不差**：

```
0xC00000E5 (EXCEPTION_INTERNAL_ERROR) at 00007ffdf976741ca
```

两次独立运行、不同进程、不同基址，崩溃点却完全相同 ——
这**不是**我上一轮判断的"写入撕裂"（那会是随机的）。
撕裂假设被证伪，必须换方向。

### 关键事实：我们改的不是模块本体

两次命中的地址不同，但**相对各自映像的 RVA 都是 `0x33e06a0`**：

| 命中地址 | 映像基址 | RVA | 区域类型 |
|---|---|---|---|
| `0x06f306a0` | `0x03b40000` | `0x33e06a0` | **MEM_MAPPED**（壳的映射视图） |
| `0x1433e06a0` | `0x140000000` | `0x33e06a0` | **MEM_IMAGE**（模块本体） |

`0x6f306a0` 那处是 `MEM_MAPPED` —— 壳把 PE 映射成**文件映射视图**。
它和磁盘文件共享底层页：往它上面写，在某些情况下会**改到文件映射的共享页**，
而不是像 `MEM_IMAGE` 那样安全地走写时复制。这解释了为什么客户端在别处崩、
为什么我们自己的回读校验查不出来（回读走的是同一个视图，看到的当然是改后的内容）。

### 改动（v9）

1. **优先选 `MEM_IMAGE` 那一处**。排序规则改为：语义分 → 是否模块本体 → 命中次数。
   报告和日志会列出**所有候选**（地址/语义分/区域类型/RVA/Protect），不再只报一个。
2. 目标选择时明确打印"模块本体，写入安全"还是"映射视图，写入可能影响共享映射"。
3. **崩溃检测改成即时**。上一版只在"进程退出"时才查转储 —— 但客户端的
   Fatal Error 是**弹窗卡住进程**，进程仍然存活，所以永远查不到，用户什么判定都看不到。
   现在每 4 秒查一次，一发现新的 `c00000e5` 转储就立刻收工并给出 RIP 判定。

### 再次踩到的 cmd 编码陷阱（已硬性拦住）

两次的报错其实是同一个原因：**中文顿号 `、`（U+3001）**。

```
echo 1、登录，在角色选择界面来回切几个角色     ->  '回切几个角色' is not recognized
echo [2/4] 启动客户端、装探针、开始记录        ->  '、装探针、开始记录' is not recognized
```

`cmd.exe` 在 `chcp 65001` 下解析 `echo` 里的顿号会错位，把后半句当成命令执行。
全部换成逗号，并在 `build-package.sh` 里加了**字节级硬检查**：三个 `.cmd` 里
只要出现 `U+3001` 的 UTF-8 字节序列（`E3 80 81`）就拒绝打包。
这个检查在 Linux 上可验证，已用"含顿号/不含顿号"两个样例双向确认过。

### 如果 v9 还崩

那结论就很明确了：**不是写入方式的问题，是 hook 这个函数本身有问题**。
下一步不再改 detour，而是先只做「读目标函数地址、不写任何字节」的验证，
确认客户端在完全不改代码的情况下能否正常运行，把变量一个个隔离掉。

---

## 第三次崩溃：v9 的选点逻辑有硬伤（Protect 0x04 根本不可执行）

v9 的日志第一次把两处候选都打出来了，也第一次暴露了真正的问题：

```
0x0000000006f406a0  语义 8/8  MEM_MAPPED(映射视图)  RVA 0x33e06a0  Protect 0x4
0x00000001433e06a0  语义 8/8  MEM_MAPPED(映射视图)  RVA 0x156a0    Protect 0x20
[成功] 目标 0x0000000006f406a0（语义分 8/8，映射视图，写入可能影响共享映射）
```

`Protect = 0x04` 是 **PAGE_READWRITE —— 这一页根本不可执行**。

我的选点规则是「语义分 → 是否 MEM_IMAGE → 先出现的」。两处都不是 MEM_IMAGE，
语义分都是 8，于是按"先出现的"选了第一处 —— **把 14 字节跳转写进了一块数据页**。
客户端永远不会执行那里的代码，而那块数据页本身可能是壳的映射/校验数据。
这就是三次崩溃的真正原因，跟"写入撕裂""MEM_MAPPED 共享"都无关。

### 同时纠正一个观测错误

v9 我心里认定「`0x1433e06a0` 是 MEM_IMAGE 模块本体」，但日志显示**它也是 MEM_MAPPED**，
且 `RVA 0x156a0`（不是 `0x33e06a0`）。也就是说之前那套"同一份代码被映射两次"的推断，
在 12.0.7 的这个壳上**不成立** —— 两处命中的 RVA 本来就不一样。

### v10 的改动

1. **可执行是硬条件**：`Protect` 不含 `PAGE_EXECUTE*` 的候选直接标「不可执行·不能用」，
   并在选点时拒绝安装（不再"选一个试试"）。
2. **写入前一致性验证**：装之前重新读目标处 13 字节，必须等于目标函数的序言
   （`48 89 5C 24 08 57 48 83 EC 20 48 8B F9`）。不一致 = 这块内存已被壳重新映射或解密，
   **拒绝写入**并打印期望/实际字节。
3. **候选字节 dump**：把所有候选前后各 128 字节写进 `wowmod\probe-hits.txt`。
   这样即使还是崩，我们手上也有"我们改的到底是什么"的第一手数据，
   而不是像前三次那样只能推断。

### 关于 cmd 报错（第三次）

顿号换成逗号后报错变成 `'，装探针，开始记录' is not recognized` —— 说明
**问题不在顿号字符本身，而在这类全角标点在 `chcp 65001` 的 echo 里会被当成命令分隔**。
所以进度行改成纯 ASCII（`[2/4] launching client and installing probe ...`），
从根上避开，不再依赖"哪些标点安全"这种经验判断。

### 需要说清楚的一件事

这三次失败都是我造成的，根源是**我在没有验证「目标页是否可执行」的情况下就去写内存**。
`Protect` 这个字段从 v6 起就已经取到了，但我只把它打印出来、没有拿它做判断。
v10 起它是硬条件。

如果 v10 仍然崩，`probe-hits.txt` 会告诉我们两处命中的真实差异；
届时我会先做**纯只读**验证（不写任何字节），确认客户端本身能正常运行，
再把变量一个个隔离 —— 不再在你机器上试错。

---

## 探针成功：1895 次调用，但拿到了一个**否定结论**

v10 的探针**装上了、没崩、正常卸载**，客户端完整跑完：

```
0x00000001433e06a0  语义 8/8  可执行  Protect 0x20
0x0000000006ec06a0  语义 8/8  【不可执行·不能用】  Protect 0x4
[校验] 目标序言与扫描时一致（13 字节），可以安全安装
```

「可执行是硬条件」这条改动直接解决了问题 —— 选中的是 `Protect 0x20`
（`PAGE_EXECUTE_READ`）那一处，而不是数据页。

结果：**1895 次调用、1423 个唯一 FileDataID、id 范围 130718 ~ 7713991**，
全程无崩溃，退出时成功卸载。

### 但把 id 拿去和 listfile 对账，结论是反的

用 `wowdev/wow-listfile` 的 `parts/*.csv`（`fileId;filePath` 格式）做了匹配：

```
探针: 1895 次调用, 1423 个唯一 FileDataID
listfile: 696083 个已知 id
可查到路径的 id: 785/1423 = 55.2%

按调用次数分布:
     991 次   interface/
     189 次   sound/
       3 次   (其它.blp)
       2 次   fonts/

character/ 开头: 0 个
```

高频 id 长这样：

```
4624242  x10   Interface/HUD/UIActionBarFXx2.BLP
5321221  x7    Interface/HUD/UIUnitFrameTargetManaMask2x.BLP
134400   x7    Interface/ICONS/INV_Misc_QuestionMark.blp
130870   x6    Interface/BUTTONS/UI-TempEnchant-Border.blp
```

**这个函数加载的是界面贴图和音效，没有一个 `character/` 资源。**

### 所以 `0x33e06a0` 不是我们要找的函数

这解释了为什么之前所有尝试都没能让血精灵模型变样：

| 事实 | 含义 |
|---|---|
| 它是按 `edx` 查哈希表的函数 | 确实是 FileDataID 查找，但**查的是"界面/音效"那一套表** |
| 1423 个 id 里 0 个是 `character/` | 角色模型贴图**根本不走这条路径** |
| 血精灵女性 `.blp` 的 id 在 `116921` 起 | 这些 id 在探针记录里一次都没出现 |

之前"Arctium 的 `CustomFileIdHook` 唯一 8/8 命中"这个判断，**在语义上是对的**
（它确实是 `edx=FileDataID` 的哈希查找），但**我们误以为它是唯一的资源查找入口**。
12.0.7 的资源查找分散在多套表里，这个只是其中一套。

### 需要承认的两点

1. 前三次崩溃是我造成的：在没检查 `Protect` 是否可执行的情况下就写内存做实验。
   现在「可执行」是硬条件，并且写入前会重新校验 13 字节序言。
2. 这一个 hook 点已经可以判定为**不适用于模型替换**。继续在它上面做替换是白费力气。

### 新增工具：`tools/listid.py`

把「探针 id ↔ listfile」对账这件事固化成可复现的命令，不再靠人肉 grep：

```bash
# 下载 listfile 分片
git clone --depth 1 --filter=blob:none --sparse https://github.com/wowdev/wow-listfile
cd wow-listfile && git sparse-checkout set --no-cone /parts/misc.csv /parts/interface.csv ...

# 对账：问"这个函数有没有加载角色模型贴图"
python3 tools/listid.py --probe wowmod-probe.txt --listfile parts/*.csv \
                        --filter character/bloodelf/female
```

无命中时它会直接给结论：

```
== 过滤 'character/bloodelf/female' ==
  listfile 中匹配的 id 总数: 1175
  探针抓到其中: 0 个

  结论: 这个函数【完全没有】加载该类资源。
        在这条路径上做替换是无效的 —— 客户端不从这里取这些文件。
        需要换目标：找到真正加载该类资源的那个函数。
```

### 下一步（方向变了）

有了 `tools/listid.py` 这个"判据"，下一步是**在内存里找另一处 FileDataID 查找函数**，
它的判据很明确：

1. 同样能被 `edx`（或其它寄存器）传入 FileDataID 的形式识别
2. 装上探针跑一遍，`--filter character/` **必须有命中**

也就是说：**先证明它会加载 `character/`，再谈替换**。
不再靠"特征码命中就上"这种赌法。

### 顺带修复：cmd 报错的真正原因

三次报错最终定位到同一件事：**`chcp 65001` 下 `echo` 行里的全角标点
（`，`、`、`、`；`）会让 cmd.exe 解析错位**，把后半句当命令执行。
不是某个字符的问题，是这类标点都会被当分隔符。

处理：进度行改纯 ASCII；并加了一条**通用硬门禁** —— 三个 `.cmd` 里
只要 `echo` 行出现 `E3 80 8C`（，）/ `E3 80 81`（、）/ `EF BC 9B`（；）的字节序列，
就拒绝打包。已用"含全角逗号/纯 ASCII"两个样表双向验证。

---

## 第二次探针：换用 FNV 那张表（`--target FileIdLookupFNV`）

### 先确认第一次的结论不是偶然

第二次探针（v10）跑了 **2844 次调用 / 1881 个唯一 id**，用 listfile 对账：

```
可查到路径: 1140/1881 = 60.6%

按调用次数分布:
    1591 次   interface/
     354 次   sound/
       5 次   fonts/
       3 次   (其它.blp)

--filter character/       -> listfile 里匹配 51305 个 id, 探针抓到 0 个
--filter character/bloodelf -> listfile 里匹配 3216 个 id, 探针抓到 0 个
```

两次独立运行、共 4739 次调用，`character/` **一次都没有**。
`CustomFileIdHook` 那个函数（RVA `0x33e06a0`）可以**判定为不适用于模型替换**。

### `probe-hits.txt` 给出了新线索

v10 新增的候选字节 dump 立刻有了回报。在目标函数**前面 0xE0 字节**处，
是另一张完全不同的 FileDataID 哈希表：

```asm
1433e05c0: 48 89 5c 24 08        mov  [rsp+8], rbx
1433e05c5: 48 89 74 24 10        mov  [rsp+0x10], rsi
1433e05ca: 48 89 7c 24 18        mov  [rsp+0x18], rdi
1433e05cf: 4c 8b 11              mov  r10, [rcx]              ; 表对象
1433e05d2: 48 b8 25 23 22 84 e4 9c f2 cb  movabs rax, 0xcbf29ce484222325  ; FNV-1a offset
1433e05dc: 44 8b da              mov  r11d, edx               ; ★ 键 = edx
1433e05e0: 44 0f b6 c2           movzx r8d, dl
1433e05e4: 33 f6                 xor  esi, esi
1433e05e6: 4c 33 c0              xor  r8, rax
1433e05e9: 48 ba b3 01 00 00 00 01 00 00  movabs rdx, 0x100000001b3       ; FNV prime
1433e05f6: 41 8b c3              mov  eax, r11d
1433e05f9: 4c 0f af c2           imul r8, rdx
1433e05fd: c1 e8 08              shr  eax, 8                  ; ★ 第 2 字节
1433e0610: 4c 0f af c2           imul r8, rdx
1433e0614: c1 e8 10              shr  eax, 0x10               ; ★ 第 3 字节
1433e0620: 48 c1 e8 18           shr  rax, 0x18               ; ★ 第 4 字节
1433e062f: 49 8b 52 08           mov  rdx, [r10+8]
1433e0633: 4c 23 c3              and  r8, rbx
1433e0636: 49 6b c0 2c           imul rax, r8, 0x2c          ; ★ 元素步长 44 字节
1433e063d: 8b 48 08              mov  ecx, [rax+8]           ; 键在 +8
1433e0640: 85 c9                 test ecx, ecx
1433e0642: 74 2a                 je   ...                    ; 空槽
1433e064d: 83 f9 ff              cmp  ecx, -1
1433e0652: 41 3b cb              cmp  ecx, r11d              ; ★ 与完整键比较
1433e0657: 49 ff c1              inc  r9
1433e065a: 4d 03 c1              add  r8, r9                 ; ★ 线性探测
```

**这是标准的 FNV-1a 32 位哈希 + 开放寻址表**，键来自 `edx`，
元素 44 字节、键在 `+8`、空槽用 `-1` 表示。

### 两张表的区别

| | `CustomFileIdHook` (0x33e06a0) | `FileIdLookupFNV` (0x33e05c0) |
|---|---|---|
| 哈希 | murmur（`ff51afd7ed558ccd`） | **FNV-1a**（`cbf29ce484222325` / `100000001b3`） |
| 键来源 | `edx` | `edx`（另存 `r11d` 二次比较） |
| 元素 | 桶指针 8B + 节点 16B | **元素 44B，键在 +8** |
| 空槽标记 | 链表 NULL | **`-1`** |
| 探测方式 | 链式 | **开放寻址（线性探测）** |
| 在调用链里的位置 | 第二个查找 | **第一个查找** |

两张表结构确实完全不同 —— 但**不是按资源类别分表**。这一点后来搞清楚了，
见下一节。

### 新特征码（31 字节，全映像唯一命中）

```
48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 4C 8B 11
48 B8 25 23 22 84 E4 9C F2 CB 44 8B DA
```

用 113 MB dump（28.4% 明文）验证：**全映像只命中 `0x33e05c0` 一处**。

### v11 的变化

1. 特征码表新增 `FileIdLookupFNV`
2. `--mode probe --target FileIdLookupFNV` 可指定目标（默认已切到 FNV）
3. 序言校验按目标分别校验（两个函数前 13 字节不同）
4. `wowmod-probe.cmd` 默认用 FNV 目标

### 判定标准（这次是明确的）

跑完 `wowmod-probe.cmd` 之后：

```bash
python3 tools/listid.py --probe wowmod-probe.txt \
                        --listfile parts/*.csv --filter character/bloodelf
```

- **有命中** → 这就是模型贴图的查找入口，可以开始做替换
- **仍然 0 命中** → 说明还有第三张表，继续按同样方法找（`probe-hits.txt` +
  探针 + listid 对账这个闭环已经跑通了）

这个闭环的关键是：**先证明它会加载 `character/`，再谈替换**。不再靠特征码命中就上。

---

## 更正：Arctium 到底怎么让模组生效（v12）

前面几轮一直在找「哪个函数负责加载 `character/`」，并据此判断
`0x33e06a0` / `0x33e05c0` 能不能用来换模型。**这个方向本身是错的。**

拿到 Arctium 的 mod 加载器源码（`Arctium/WoW-Launcher`，MIT，2024 年删库，
现存于 fork `Longee-G/Arctium-WoW-Launcher-No-Certificate-Requirements`）之后，
它的做法一目了然 —— 它**不 hook 查找函数，也不替换返回值**：

```csharp
// src/Launcher.cs
Task.WaitAll(new[] {
    memory.QueuePatch(Patterns.Windows.LoadByFileIdAlternate,
                      Patches.Windows.NoJump, "LoadByFileId", 3),
    memory.QueuePatch(Patterns.Windows.LoadByFilePathAlternate,
                      Patches.Windows.NoJump, "LoadByFilePath", 3)
});

// src/Patches/Windows.cs
public static byte[] NoJump = { 0x00, 0x00, 0x00, 0x00 };
```

它把那两处「按 FileDataID / 按路径从 CASC 加载」的 `je rel32`
**改成 `je 0`（永不跳）**。于是函数跳过整段 CASC 读取逻辑，
返回 false，上层认为「CASC 里没有这个资源」，转而去查
`mappings/*.txt` + `files/` 里登记的本地文件。

### 12.0.7 上这两条特征码都在

用 113,565,696 字节的主模块解密映像逐条验证：

| 特征码 | 命中数 | 地址 | 补丁点 | 原字节 |
|---|---|---|---|---|
| `LoadByFileIdAlternate` | **1** | `0x33d7976` | `0x33d797a` | `0F 84 9C 00 00 00`（`je 0x33d7a19`） |
| `LoadByFilePathAlternate` | **1** | `0x33d7b58` | `0x33d7b5b` | `0F 84 C0 00 00 00`（`je 0x33d7c1f`） |
| `LoadByFileId`（旧） | 0 | — | — | 12.0.7 已不再使用 |
| `LoadByFilePath`（旧） | 0 | — | — | 12.0.7 已不再使用 |
| `CustomFileIdHook` | 1 | `0x33e06a0` | — | 同上，是**另一个**用途 |

### 为什么前几轮的「0 命中」不能说明问题

`0x33d78f0` 是文件打开函数本体，`r8d`（第 4 个参数）被存进 `ebp`
（`0x33d7917  mov ebp, r8d`），随后 `0x33d7973  test bpl,1` 用它决定
要不要走 CASC 分支。

探针装在下游的两个查找函数上（`0x33e05c0` / `0x33e06a0`），
**只统计了「已经决定要走 CASC 分支」的那些调用**。界面和音效先加载、
且走这条路径，所以日志里只有 `interface/` 和 `sound/`；
角色资源要么走了另一个分支，要么在这些调用之前就被上层拦掉了。

结论：探针的「0 命中」是**测量位置的问题**，不是「这个函数不管角色资源」。
两次共 4739 次调用这个数字仍然有效，但它证明不了任何关于 `character/` 的事。

### v12 的变化

1. 新增 `--mode patch`：按 Arctium 的做法改写两条条件跳转
   （**不打 hook、不搬指令、不写跳板**，所以前三次崩溃的成因在这里不存在）
2. 新增 `wowmod-patch.cmd` 一键脚本（`--mode patch --apply`）
3. 特征码表改正：`patch_offset` 对 Alternate 变体是 **3**（不是旧版的 6），
   并把旧的 `LoadByFileId` / `LoadByFilePath` 标注为「12.0.7 不命中」
4. 三条硬性安全条件，任一不满足就跳过并写报告，绝不猜着打：
   - 全映像**唯一**命中（多处命中 = 特征太弱）
   - 补丁点当前字节必须真的是 `0F 84`（`je rel32`）
   - 写前复读 + 写后回读，不一致就回滚
5. 构建标记 `patch-v12`，主机测试 560 项 0 失败

### 还需要补的一环（诚实说明）

Arctium 的 `ModLoader.HookClient` 在打完这两条补丁之后，还会在
`CustomFileIdHook`（= `0x33e06a0`）入口装一个 15 字节 jmp 到它自己的查表
stub：拿 `edx` 在它注入的 `idAlloc` 表（每项 12 字节：4 字节 id + 8 字节
路径指针）里线性查找，命中就返回路径指针。**这一层 v12 还没有做** ——
它需要正确的「查不到时返回什么」语义，直接替换返回值会拿垃圾指针当资源用。

所以 v12 的定位是：**先把「关闭 CASC 分支」这一半做对、做安全**，
并且用实测数据确认它在 12.0.7 上确实命中。这一半是 Arctium 机制里
唯一「改动极小、可验证、不会崩」的部分。下一半要等这一半的实测结果。

---

## v13：为什么第一次跑 patch 模式「命中 10 处」

第一次实测（v12，`patch-v12`）报告：

```
[LoadByFileIdAlternate]
  [SKIPPED] 特征码命中 10 处，不唯一，拒绝安装
[LoadByFilePathAlternate]
  [SKIPPED] 特征码命中 2 处，不唯一，拒绝安装
```

**没有崩溃、没有写入一个字节** —— 安全门按设计生效了。但这个数字和离线
映像里「各 1 处」对不上，原因查清了：**不是客户端的问题，是我们用错了签名。**

### 根因：Arctium 的特征码通配位太多

```
01 0F 84 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 8B ?? E8
 ^^^^^^ 固定    ^^^^^^^^^^^^^^^^^^^^^^^^^ 全是通配
```

17 个字节里 **13 个是通配位**，实际只约束了 `01 0F 84` 和 `48 8B` 这几个字节。
Arctium 自己只扫**主模块**（约 113 MB、单一副本），所以这样够用；
而我们要覆盖「壳把代码解密到别的分配」的情况，得扫全进程可执行区
（200+ MB，同一段代码可能有多个副本），于是一个只约束 4 个字节的串
命中十几次是必然的。

### 修正：加一条无通配的长签名

从 12.0.7 解密映像逐字节反汇编导出，**完全没有通配位**：

| 签名 | 长度 | 离线命中 |
|---|---|---|
| `01 0F 84 9C 00 00 00 48 8B 0D 4C 01 FD 00 8B D6 E8 15 8D 00 00 48 85 C0 74 05 49 8B FC EB 20 48 85 FF 0F 84 CF 00 00 00 48 8B 17 45 33 C0 48 8B 0D 25 01 FD 00` | 53 B | `0x33d7976`，**1 处** |
| `01 0F 84 C0 00 00 00 48 8B 0D 6A FF FC 00 44 89 A4 24 C0 00 00 00 48 85 C9 0F 84 A8 00 00 00 4C 8D 84 24 C0 00 00 00` | 39 B | `0x33d7b58`，**1 处** |

两份独立 dump（`main-module3.rar` / `main-module2.rar`，各 113,565,696 B）交叉
验证，都是 1 处。强签名找不到时才退回 Arctium 原始特征码。

### 三层判定，逐级降级

1. **精确长签名** → 命中 1 处直接用
2. **离线确证 RVA**（`0x33d7976` / `0x33d7b58`）→ 多处命中里 RVA 对上的那个就是本体
3. **上下文分组** → 同一段代码被映射多份（前 16 字节一致）时仍拒绝，提示用 `--rva` 点名

### 报告现在会列出每一处命中

不再只给一句「命中 10 处」，而是逐条给出：

```
命中 10 处:
    #1  VA 0x14033D797  rva 0x33d7976  (匿名区) MEM_IMAGE 可执行
        上下文 ...
    #2  ...
```

有了这些 RVA，即使自动判定拒绝，也能人工用 `--rva Name=0x...` 指定。

### v13 的变化

1. `arctium_sigs.hpp` 增加 `strong_pattern` / `known_rva` / `known_build`
2. `plan_branch_patches()` 支持 `--rva NAME=0x...` 人工点名
3. 报告列出每一处命中（VA / RVA / 模块 / 是否 MEM_IMAGE / 是否可执行 / 上下文）
4. 报告记录 `je 目标` —— 能直接看出它跳过了哪一段代码
5. 主机测试 574 项 0 失败，构建标记 `patch-v13`
