# Arctium 的做法 vs. 本项目（12.0.7 Firestorm 68974）

## 1. Arctium 的机制，逐步拆开

来源：`brian8544/Arctium-Launcher`、`ModernWoWTools/Launcher`、
`redscarf26/arctium-wow-launcher` 中 `src/ModLoader.cs` 的 `CustomFileIdHook` 流程。

1. **挂起创建** `Wow.exe`（`CREATE_SUSPENDED`）。
2. `VirtualAllocEx` 一块 RW 内存，写入本地文件表：
   每条 16 字节 `{u32 fileDataId, u32 pad, u64 pathPtr}`，路径字符串单独一块，
   随后把整块 `VirtualProtectEx` 成 `PAGE_READONLY`。
3. 在磁盘 exe 上按 **字节特征** 找 `LoadByFileId`：

   ```
   LoadByFileId = 41 ?? ?? 01 0F 84 ?? 00 00 00 48 8B ?? ?? ?? ?? ?? 8B
   ```
4. 把函数开头 **13 字节** 换成 `48 B8 <abs64> FF E0 90`（`mov rax,imm64; jmp rax`），
   原始的 13 字节搬进 trampoline。
5. 跳板里：拿 `EDX` 当 FileDataID，扫表，命中返回本地路径指针，未命中跳回 trampoline。
6. `ResumeThread`。

它对客户端的要求就两条：**磁盘特征能匹配**、**ID 在 EDX 里**。

## 2. 为什么这里两条都不成立

用 `firestorm-runtime-dumps.zip` 里的真实转储逐区域核对（文件名/大小/RVA 都在
`docs/ARCHITECTURE.md`）：

* 模块表主模块基址 `0x140000000`，`SizeOfImage 0x6c4e000`；
* 但**含 `WOWSTATIC_12_0_7_67808` 标记、含真实数据的块在 `0x118000000`**，
  是一个独立分配，不在主模块映像内；
* 磁盘 `.text` 是自解压/加密壳，版本 68974 的代码在运行时才被替换进来，
  静态基座是 **67808**（`WOWSTATIC_PATCH_12_0_7` @ `0x489dd90`）。

结论：
1. 磁盘上写的特征码在这个构建上**没意义**（代码还没生成）；
2. 运行时地址每次都变，写死 RVA 也没意义；
3. `EDX` 作为 FileDataID 是旧版假设，没有证据支持。

所以"照抄 Arctium"必然失败。Arctium 没做错什么——它面对的是 `.text` 明文、
代码与磁盘一致的客户端。

## 3. 本项目的对应实现

| Arctium 的步骤 | 本项目的实现 | 差异原因 |
| --- | --- | --- |
| 挂起创建 | `launcher_main.cpp` 同 | 不变 |
| 写本地文件表 | `fd_hook.cpp: write_remote_string_table` + id 表 | 改为 `{u32 id, u64 path}` 紧凑布局，减少一次写入 |
| 磁盘特征匹配 | **不用**；`scan_images.cpp` 枚举进程所有区域，挑含标记字符串的那块 | 磁盘代码不可信 |
| 定位 `LoadByFileId` | `xref` 找「引用 `Locally overridden files` 的函数」；`xref.cpp` 的 id 扫描器再按 `cmp [base+idx*4]` + 函数距离 + `ret` 可达 打分 | 不知道函数名，就用语义锚点 |
| 写死 13 字节 | `x64_decode::find_safe_split`，按真实指令边界算覆盖长度 | 13 字节在别的构建上会切断指令 |
| 写死 `EDX` | 可配置 `WOWMOD_RT_IDREG`；**默认不猜**，先用拦截模式实测 | 没有证据 |
| 无回滚 | `fd_hook.cpp` 7 步全部有回滚 | 可实测 |

## 4. 与 Arctium 相同的输入，不同的证据链

两边最终输入都是 `fileId;filePath` 列表
（`examples/12.0.7/mappings/listfile.txt`，89 条，来自 `wowdev/wow-listfile`），
但**本项目不接受"照抄就算实现"**：每一条被改写进客户端进程的字节，都必须在
真实运行的内存上重新分析出来，否则拒绝安装（`fd_hook.cpp` 里
`find_safe_split` 返回 0 就直接放弃，一个字节都不写）。

## 5. 已知还需要逆向的一件事

FileDataID 的真实参数位置与返回语义。`--mode auto` 的拦截日志就是为这件事设计的，
见 README §5–§6。
