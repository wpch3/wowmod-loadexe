# x64dbg：给这个加密壳客户端定位 FileDataID hook 点

> 适用对象：`WoW 12.0.7 - Firestorm.exe` + `wow_loader.dll`。
> 前提：**只在你有权调试的私服 / 离线环境里做**，不要用于官方服或有反作弊的客户端。
> 这一步是可选的 —— `wowmod.exe launch` 的 `hooks.runtimeScan` 会自动完成下面的
> "转储解密内存"，x64dbg 主要用来人工确认「哪个寄存器是 FileDataID、返回值是不是路径指针」。

## 背景（为什么不能用静态扫描）

- exe 的 `.text` 是 53 MB、熵 ≈ 8.00 的密文，磁盘开头是 `2D 18 D1 12 99 96 8F B9 …`；
  明文 `DBFilesClient`、`FileData ID %d %s` 只留在 `.rdata`。
- `wow_loader.dll` 是真正的加载层，字符串被剥光。
- 所以**磁盘上不存在可引用的明文代码**，IDA/Ghidra/静态 `discover` 都会得到 0 个 xref。
  必须在进程把代码解密到内存之后再分析。

## 0. 准备

- 下载 [x64dbg](https://x64dbg.com/) 的 release，用 **x64dbg.exe（64 位）**；客户端是 x64。
- 用**原版启动方式**（直接双击 exe 或 x64dbg 打开），**不要经过 `wowmod launch`**，
  否则我们的 IAT hook 会干扰你对 `CreateFileW` / `NtCreateFile` 的观察。
- 以管理员身份运行 x64dbg（有完整性/保护检查时需要）。
- 先把 `wowmod.exe detect --config ... --json` 跑一遍，记下 `client.arch` 应为 `x64`。
  记录主模块基址的方法见第 3 步。

## 1. 用 "Open" 而不是 "Attach"

`File → Open` 选择 `D:\Midnight Open Beta\_midnight_\WoW 12.0.7 - Firestorm.exe`：

- **Command line**：填你私服的启动参数；没有就留空。
- **Current directory**：**必须**设为 `D:\Midnight Open Beta\_midnight_\`（否则找不到 `wow_loader.dll` 和 `Data\`）。

x64dbg 会在系统断点（进程刚创建、主线程尚未跑）停住。此时 `.text` 还是密文。

## 2. 断在「解密完成」的那一刻

在底部命令栏输入（回车执行）：

```
bp VirtualProtect
bp NtProtectVirtualMemory
```

`F9` 运行，观察每次断下时的参数。加密壳的典型行为：

```
VirtualProtect( <主模块 .text 地址>, <大长度>, PAGE_READWRITE, ... )   ← 准备写入
... 解密/解压 ...
VirtualProtect( <同一地址>, <大长度>, PAGE_EXECUTE_READ, ... )          ← 写完了，改回可执行
```

当看到 `NewProtect = PAGE_EXECUTE_READ (0x20)` 且地址落在主模块 `.text` 范围内时，
解密基本完成。**更保险的做法**：一直 `F9` 到登录界面 / 进入角色界面，再暂停
（游戏代码这时肯定已经解密）。

### 判断有没有解密（重要）

`Alt+M` 打开内存映射 → 双击主模块 `.text` → 看十六进制窗口开头：

| 看到的内容 | 结论 |
| --- | --- |
| `2D 18 D1 12 99 96 8F B9 15 AC 54 31 D9 A7 D2 B8 …` | **还是密文**，继续 `F9`，或换个更晚的时机再 dump |
| `48 89 5C 24 08`、`41 57 41 56`、`48 81 EC …`、`40 53` | 正常 x64 函数序言 → **已解密** |

解密可能是分阶段 / 按需的；如果 dump 出来 `wowmod discover --mapped` 仍是
`xrefCount=0`，多半就是 dump 得太早。

## 3. 转储内存映像（这一步能直接交给我）

`Alt+M` → 找到主模块 `WoW 12.0.7 - Firestorm.exe`：

- 记下 **Base**（例如 `0000000140000000`）
- 记下 **Size / SizeOfImage**（PE 头 `OptionalHeader.SizeOfImage`；
  也可以用 `wowmod.exe scan --json` 看节区范围）

导出**从模块基址开始、长度 = SizeOfImage** 的整块内存。两种方式：

**方式 a（命令，最准）**

```
savedata "D:\dumps\main.exe.img", 0000000140000000, 0x26B0000
```

`savedata` 语法是 `savedata 文件名, 起始地址, 字节数`（地址和大小换成你的实际值）。

**方式 b（GUI）**

内存映射里右键主模块区域 → `Dump Memory to File` → 存成 `main.exe.img`。

对 `wow_loader.dll` 再重复一次，存 `wow_loader.dll.img`。

> ⚠ **必须从模块基址开始、覆盖整个 SizeOfImage**。这样"文件偏移 == RVA"，
> 我们的 `PeImage(mapped=true)` / `--mapped` 才能正确解析。如果 x64dbg 只导出了
> 单个节区，请同时告诉我节区名和 RVA，别当成完整映像。

验证 dump 是否可用（任意机器上都能跑）：

```powershell
.\wowmod.exe discover --exe D:\dumps\main.exe.img --mapped --json
```

看 `anchorsFound` 和 `xrefCount` 是否 > 0。若还是 0，回到第 2 步等更晚再 dump。
`--emit hooks\patterns.runtime.json` 会把候选特征写出来。

> 其实这一步 `wowmod launch` 会**自动做**：配置里 `hooks.runtimeScan: true` 时，
> 注入 DLL 后台线程用 `VirtualQuery` + `ReadProcessMemory` 转储主 exe 和
> `wow_loader.dll`，写到 `examples\12.0.7\runtime-dumps\`。把那个目录发我即可，
> 不需要手工 x64dbg。

## 4. 找到「按 FileDataID 打开」的函数（人工确认语义）

1. 在反汇编窗口右键 → `Search for` → `All referenced text strings`
   （或 `Ctrl+F` 直接搜 ASCII），找这些锚点：

   ```
   DBFilesClient
   FileData ID %d %s
   addons.txt
   WTF/Config.wtf
   Unable to open
   ```

2. 双击引用 → 看是哪条 `lea reg, [rip+disp]` 指向该字符串。向上滚到**函数入口**
   （x64dbg 会画函数边界；常见开头 `48 89 5C 24 08`、`48 81 EC xx`、`41 57 41 56`）。

3. 在入口第一条指令按 `F2` 下断点，`F9` 进游戏，做一次会加载模型的动作
   （进角色、换地图、打开外观）。断下后看寄存器窗口：

   - 哪个寄存器是**小整数**（例如 `EDX = 0x0004A1B2`）？拿它去你的 12.0.7
     listfile 里对一下，对得上就是 **FileDataID 寄存器**。
   - 常见是 `edx` / `rdx`，也可能是 `ecx`、`r8d`。

4. 确认返回值：单步到 `ret`，看 `RAX` 是否指向一个 null 结尾的 ANSI 路径字符串
   （Dump 窗口 `Follow in Dump`）。只有「返回路径指针」的函数才适合我们的
   `fileid_hook`（VEH 里把 RAX 换成模组文件路径并直接返回）。

5. 更快的交叉验证：在 `CreateFileW` / `NtCreateFile` 下断，看客户端读模型时
   请求的路径，再回溯到产生这个路径的调用者。

## 5. 把这些发我就行

- 函数入口**前 24–32 字节**（x64dbg 里选中 → 右键 `Copy → Bytes`，或
  `savedata` 导出 32 字节）
- **ID 所在寄存器**（如 `rdx`）
- **模块名**（主 exe 还是 `wow_loader.dll`）以及入口 **RVA** = 地址 − 模块基址
- 可选：第 3 步的 `.img` / `runtime-dumps\`

我会把它写成 `patterns.json` 条目，用 `wowmod scan` 验证唯一匹配，再决定是否启用
`fileid` 模式。在此之前加载器保持纯 VFS，不会自动下断点。

## 常见坑

| 坑 | 处理 |
| --- | --- |
| dump 出来还是密文 | 解密分阶段；等到进入角色界面再 dump，用第 2 步的字节判据确认 |
| `xrefCount=0` | 太早 dump；或游戏代码被解密到**模块之外**的新申请可执行内存 |
| 代码不在模块范围内 | `Alt+M` 找 `PAGE_EXECUTE_READ` 的**私有提交**区域（不属于任何模块），逐个 `savedata` 出来并告诉我基址 |
| 在 `LoadLibraryW` 上用硬件断点 | 我们的注入也走 `LoadLibraryW`，会互相干扰；静态分析时别用它 |
| `wow_loader.dll` 还没加载 | 它通常是静态导入，进程早期就在 `Alt+M` 里；若没有，先 `F9` 到 `LoadLibrary` 之后 |
| 位数不对 | 用 x64dbg.exe（64 位），客户端是 x64 |
| 想省事 | 直接用 `wowmod launch` 的 `runtimeScan` 自动转储，把 `runtime-dumps\` 发我 |

---

`discover` / `--mapped` 产出的都是**启发式候选**：唯一字节匹配不等于函数语义正确。
首次进游戏前请务必完成第 4 步的寄存器 / 返回值确认。
