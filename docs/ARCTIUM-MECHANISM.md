# Arctium「自定义文件」机制完整拆解

本文是**逐字节**拆解，不是概括。来源：

| 来源 | 内容 |
|---|---|
| `arctoim-all.7z.001~004`（用户提供，97 MB） | Arctium 新版启动器整套文件 |
| `Longee-G/Arctium-WoW-Launcher-No-Certificate-Requirements` | 旧版开源实现（`ModLoader.cs`、`Patterns/Windows.cs`） |
| 用户上传的 `probe-hits.txt` | 12.0.7 真实内存字节，用于交叉验证 |

---

## 0. 先说结论：这是两半，缺一不可

Arctium 让本地文件生效，需要**同时**完成两件事：

```
第一半：把「从 CASC 加载」的条件跳转改掉         <- 只改变控制流
第二半：把 FileDataID -> 本地路径 的查表装进进程  <- 提供数据
```

**只有第一半，客户端会认为「CASC 里没有、本地也没有」。**
**只有第二半，客户端根本不会去查表。**

这是本项目的核心教训：前几轮只做了第一半，所以无论怎么调都无法生效。

---

## 1. 第一半：NoJump 补丁

`Patches/Windows.cs`：

```csharp
public static byte[] NoJump = { 0x00, 0x00, 0x00, 0x00 };
```

它替换的是 `je rel32` / `jne rel32` 的 **rel32 部分**（4 字节），
使 `rel32 = 0`，即「跳转到下一条指令」—— 分支永不成立。

`Launcher.cs` 的选择逻辑：

```csharp
(clientVersion is (10, _, _, _))
    ? memory.QueuePatch(Patterns.Windows.LoadByFileIdAlternate,  Patches.Windows.NoJump, "LoadByFileId",   3)
    : memory.QueuePatch(Patterns.Windows.LoadByFileId,           Patches.Windows.NoJump, "LoadByFileId",   6),

(clientVersion is (10, _, _, _))
    ? memory.QueuePatch(Patterns.Windows.LoadByFilePathAlternate, Patches.Windows.NoJump, "LoadByFilePath", 3)
    : memory.QueuePatch(Patterns.Windows.LoadByFilePath,          Patches.Windows.NoJump, "LoadByFilePath", 3)
```

**第三个参数（3 / 6）是特征码里跳到 `je` 操作码的偏移。**
`0F 84 imm32` 共 6 字节，`je` 操作码在 `+0`，`rel32` 在 `+2`。
所以两者关系：

```
patch_offset = je_opcode_offset + 2
```

本项目 12.0.7 实测：

| 目标 | 匹配 RVA | `je` 操作码 RVA | rel32 RVA（= 补丁点） | 原 rel32 |
|---|---|---|---|---|
| `LoadByFileIdAlternate` | `0x33d7976` | `0x33d7977` | `0x33d7979` | `9C 00 00 00` |
| `LoadByFilePathAlternate` | `0x33d7b58` | `0x33d7b59` | `0x33d7b5b` | `C0 00 00 00` |

---

## 2. 第二半：查表 stub（这才是「引擎」）

### 2.1 表结构

`ModLoader.LoadFileMappings` + `AllocateFileMapping`：

```csharp
var idAlloc     = VirtualAllocEx(handle, 0, count * (4 + 8), MEM_COMMIT, PAGE_READWRITE);
var stringAlloc = VirtualAllocEx(handle, 0, stringLength,     MEM_COMMIT, PAGE_READWRITE);
```

每个条目 **12 字节**：

```
偏移 +0 .. +3    uint32  FileDataID
偏移 +4 .. +11   uint64  指向 stringAlloc 里的路径字符串（存的是绝对地址）
```

写完两边都 `VirtualProtectEx(..., PAGE_READONLY)` —— **只读**。

条目顺序 = `mappings/*.txt` 的读取顺序，**没有排序**。
这一点很重要：stub 用的是**线性扫描**，最多 `0xDEADBEEF` 次。

### 2.2 安装位置

```csharp
var hookAddress = memory.Data.FindPattern(Patterns.Windows.CustomFileIdHook);
var originalBytes = memory.Read(memory.BaseAddress + hookAddress, 13);
```

在 `CustomFileIdHook` 命中处写 **13 字节**：

```
48 B8 <u64 跳板地址> FF E0 90      ; mov rax, imm64 ; jmp rax ; nop
```

### 2.3 跳板布局（关键，且和我们之前的做法不同）

```csharp
memory.Write(trampolineInjectAddress, asm);                                   // [0]      50 字节 stub
memory.Write(trampolineInjectAddress + asm.Length,
             originalBytes.Concat(jmpInstruction).ToArray());                 // [50]     13 字节原指令
                                                                              // [63]     13 字节跳回
```

即：

```
跳板 +0x00 : 50 字节 自写查表 stub
跳板 +0x32 : 13 字节 被覆盖的原始指令
跳板 +0x3F : 48 B8 <hookAddress + base + 13> FF E0 90    ; 跳回原函数 +13
```

**注意：13 字节原指令放在 stub 之后，靠 `jmp` 回到原函数 +13 —— 不是「先执行原指令再进 stub」。**
另注意 `jmpInstruction` 里的最后一个是 `0x90`（nop）而非 `0xCC`。

### 2.4 stub 逐条反汇编

```asm
; ---- ecx / rdx = FileDataID ----
00  85 D2                    test   edx, edx
02  0F 88 72 AF FF FF        js     <原函数 +0>      ; 负数 id -> 直接回原函数
08  33 C0                    xor    eax, eax         ; rax = index = 0
10  49 B9 <u64 idAlloc>      movabs r9, idAlloc
20  8D 0C 40                 lea    ecx, [rax + rax*2]
23  C1 E1 02                 shl    ecx, 2           ; ecx = index * 12
26  42 39 14 09              cmp    dword [rcx + r9], edx
30  74 0C                    je     +0x3e
32  FF C0                    inc    eax
34  3D <u32 count>           cmp    eax, count
39  72 EB                    jb     +0x20            ; 循环
41  33 C0                    xor    eax, eax
43  C3                       ret                     ; 没找到 -> 返回 0 (null)
44  4A 8B 44 09 04           mov    rax, [rcx + r9 + 4]   ; 取路径指针
49  C3                       ret
```

`js <原函数 +0>` 的编码 `0F 88 rel32` 由 Arctium 在运行时算出；
在当前布局下 rel32 = `0xFFFFAF72`（= -20622），即 50 字节 stub **之后紧跟的原始指令开头**。

**语义总结：**

```
输入 edx = FileDataID
命中   -> rax = 指向 UTF-8 路径字符串的指针
未命中 -> rax = 0
负 id  -> 直接执行原函数（完全旁路，不改行为）
```

### 2.5 为什么必须在 `mov rdi, r12` 那个函数上

本项目在 12.0.7 实测到（`probe-hits.txt`）：

```
0x1433e06a0  语义 8/8  可执行=是
48 89 5C 24 08   57   48 83 EC 20   48 8B F9
```

`48 8B F9` = `mov rdi, rcx`，而**调用点从不使用 `rax` 作为返回值**（它用 `r12`，此时为 0）。
所以 Arctium 的做法不是「替换返回值」，而是**替换一个指针参数** ——
被替换的那条指令必须能接受「一个路径指针」而不是 FileDataID。

### 2.6 交叉验证：Arctium 的特征码在 12.0.7 依然有效

用 `Patterns/Windows.cs` 里的 43 字节 `CustomFileIdHook` 去匹配用户上传的真实内存：

```
特征码匹配地址: 0x1433e06a0      <- 与探针报告地址完全一致
```

**这一条是硬证据**：特征码没过期，hook 点位置正确。

---

## 3. 为什么我们之前会崩

### 3.1 确诊的部分

探针在 `0x1433e06a0` 装好后，游戏能进、能走动，随后
`EXCEPTION_INTERNAL_ERROR 0xC00000E5`，出错地址在 `ntdll` 的
`RtlReportCriticalFailure`，**不是客户端代码**。

`0x33e06a0` 是**文件加载主函数**，每个资源都会调它。在这里装跳转，
任何一次寄存器 / 栈 / 返回值不一致都会被放大成必崩。

### 3.2 我们和 Arctium 在这一点上的差异

| 项目 | Arctium | 我们 |
|---|---|---|
| 覆盖长度 | 固定 13 字节 | `find_safe_split` 求完整指令边界（此函数为 16 字节） |
| 剩余字节填充 | `0x90` (nop) | `0xCC` (int3) |
| 原指令执行时机 | stub 之后（靠 `js` 回原函数） | 跳板开头（先执行再进返回 stub） |
| 负 id 处理 | 显式 `js` 旁路 | 无 |
| 返回值语义 | 返回**路径指针**进 `rax` | 记录后返回 |

`0xCC` 填充本身在 5 字节 `jmp` 之后不可达，不是直接死因；
**真正的差异在 3、4、5 行**：我们对「返回指针」而非「返回 id」的调用约定没有跟随。

---

## 4. 需要复刻的完整序列

```
1. 读 mappings/*.txt，按 "id;path" 解析
2. VirtualAllocEx 两块：idAlloc = count*12，stringAlloc = 字符串总长+1
3. 填表：每条 [u32 id][u64 stringAlloc+偏移]，路径写进 stringAlloc（UTF-8，\\ -> /，小写）
4. 两块都 PAGE_READONLY
5. 在 CustomFileIdHook 命中处写 13 字节 jmp -> 跳板
6. 跳板 = 50 字节 stub + 13 字节原指令 + 13 字节跳回
7. stub 里回填：idAlloc 地址（偏移 12）、count（偏移 35）、js 的 rel32（偏移 4）
8. 配合第一半的 NoJump，缺一不可
```

---

## 5. 未解决 / 需要实测确认

- 12.0.7 里 `0x33e06a0` 之后**哪个 callee 接受路径指针**（Arctium 的
  `js <原函数+0>` 暗示原函数「在有 id 时也能接受指针」，需实测）。
- `count` 是用 `0xDEADBEEF` 占位再回填的，回填偏移 35 已由反汇编确认。
- 本次未验证：完整的「两半同时上」是否能生效。**这一步从未被执行过。**

---

## 6. Arctium 新版包的结构（为什么里面没有引擎）

`arctoim-all.7z`（588 文件）是 **WinUI3 启动器外壳**：

```
Arctium.App.dll        2.5 MB   UI / 账号 / 模组管理
Arctium.App.Core.dll
Arctium.Api.Client.dll
Arctium.Api.Protocol.dll
```

`Arctium.App.dll` 的类型表里有 `ModProfile` / `ModFolder` /
`CustomModMappings` / `RetailLauncherModFolders` / `ModuleFeedConfiguration`，
但 **`#US` 字符串堆只有 1148 字节、50 条**，且**没有任何特征码字节数组**。

结论：真正的「引擎」是运行时按 `ModuleFeedConfiguration` **在线下载**的 Module，
不在这个包里。上文第 1~4 节的机制来自旧版开源实现（那是同一套机制），
并用用户上传的真实内存字节做了交叉验证。

---

## 7. 复刻实现（`src/core/arctium_clone.cpp`）

不必再"参考"——代码已逐字节照抄。校验结果：

| 项 | Arctium 源码 | 我们的产物 | 一致性 |
|---|---|---|---|
| stub 模板 | `ModLoader.cs` 的 50 字节 `asm` 数组 | `arctium_stub_template()` | **逐字节相同（memcmp == 0）** |
| 回填位置 | 偏移 4 / 12 / 35 | 同 | 相同，且测试断言**三处之外一个字节都不许变** |
| hook 长度 | 13 字节 | `build_hook_jump()` | **逐字节相同** |
| hook 编码 | `48 B8 <u64> FF E0 90` | 同 | 相同 |
| 表项步长 | `4 + 8 = 12` | `EntryLayout::kStride = 12` | 相同 |
| 表项字段 | `[u32 id][u64 path]` | 同 | 相同 |
| 两块内存 | `VirtualAllocEx` + `PAGE_READONLY` | 同 | 相同 |
| 跳板布局 | `stub(50) + 原指令(13) + 跳回(13)` | 同 | 相同 |
| NoJump | `{0,0,0,0}` 覆盖 rel32 | `apply_branch_patches` | 相同 |

### 7.1 用 x64sim 跑出来的真实语义（不是读源码猜的）

```
命中第 0 项 -> ret，rax = 路径指针
命中第 1 项 -> ret，rax = 路径指针
命中第 2 项 -> ret，rax = 路径指针
未命中    -> xor eax,eax / ret，rax = 0   （【不】执行原始指令）
id == 0   -> 同上，返回 0
id 为负   -> js 跳到 +50 执行原始指令（完全旁路）
```

**注意「未命中返回 0」**：这条与直觉不同。Arctium 的 `js` 只处理负 id，
未命中走的是 `xor eax,eax / ret`。也就是说未命中的文件会得到空指针，
由客户端自己处理（回退到 CASC）。

### 7.2 两套实现的差异（可切换）

`wowmod-load.cmd` 默认走 **Arctium 原版**。
加 `--stub native` 可切到本项目生成器，后者：

- 16 字节表项（对 CPU 更友好）
- 未命中跳 `trampoline`（执行原始指令并回到原函数）
- 已用 x64sim 验证 1096 项表的**最后一项**也能命中

两套实现都有离线执行测试兜底（`tests/tests.cpp` 的
`arctium_clone` 与 `fileid_stub_semantics` 两组）。

### 7.3 仍然无法离线验证的部分

客户端拿到路径指针后做什么（是否打开文件、是否走 CASC 回退）。
这一层是客户端自己的代码，不在 Arctium 也不在我们手里。

---

## 8. 为什么 Arctium 不需要用户配合（而我们需要）

这一节回答一个反复被问的问题：「为什么要扫数据？Arctium 怎么就不用？」

**Arctium 也在扫、也在等。差别在判据。**

### 8.1 Arctium 的启动时序（`src/Launcher.cs` 原文）

```csharp
CreateProcess(..., CREATE_SUSPENDED, ...);                 // 挂起创建
using var gameAppData = new MemoryStream(File.ReadAllBytes(appPath));
var memory = new WinMemory(processInfo, gameAppData.Length); // 从 PEB 读基址
NtResumeProcess(handle);                                    // 恢复
while (VirtualQueryEx(...) == 0 || mbi.RegionSize <= 0x1000) { }  // 等区域就绪
NtSuspendProcess(handle);

WaitForUnpack(...):
    initOffset = Read(...).FindPattern(Patterns.Windows.Init) ?? 0;
    while (initOffset == 0) { 重读; }                       // 等 Init 特征码
    while (Read(initOffset + base, 1)?[0] == 0) 重读;
    memory.RefreshMemoryData((int)mbi.RegionSize);
```

### 8.2 三个关键差别

| | Arctium | 本项目过去 |
|---|---|---|
| 映像基址 | **PEB `ImageBaseAddress`**（权威，零猜测） | 猜「SizeOfImage 最大的 PE 区域」 |
| 就绪判据 | **`Patterns.Init` 特征码出现**（直接指标） | 明文页比例 ≥ 50%（间接指标） |
| 找不到时 | **无限重读直到出现** | 扫一次就失败退出 |

**「明文页比例」是我自己发明的间接指标，而且在这个客户端上永远达不到**：
惰性解密下明文页稳定在 138~139 就不再增长（没执行到的页不会解密），
占比远低于 50%，于是每次都误报未就绪。这就是连续几次 `语义分 0/8` 的成因。

### 8.3 现在的做法（照抄 Arctium）

- 基址：`NtQueryInformationProcess(ProcessBasicInformation)` → PEB + 0x10
- 就绪：反复扫 `Init` 特征码，出现即继续
- 扫描：边等边扫，拿到 `>= 6/8` 的可执行命中才收工

`Init` 特征码（Arctium 原样，25 字节）：

```
C7 05 ?? ?? ?? ?? 01 00 00 00 48 8D ?? ?? ?? ?? ?? 48 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 85
```
