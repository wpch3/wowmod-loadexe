# 为任意私服 build 适配（含 WoW 12.0.7 具体步骤）

## 12.0.7（Midnight / CASC / x64）专用流程

仓库里的 [`examples/12.0.7/`](../examples/12.0.7/README.md) 是给这个版本准备的起始包，
直接复制到游戏根目录，改 `client.portal` 就能用：

```bash
wowmod detect   --config wowmod.json     # 输出「已支持（无版本白名单）」
wowmod validate --config wowmod.json
wowmod plan     --config wowmod.json     # 路径型覆盖立刻生效，mode=vfs
```

**版本探测**：`.build.info` 里的 `Version` 一般是 `12.0.7.xxxxx`（完整 build 号会自动读到）。
如果只写了 `12.0.7`，或者你的 exe 版本资源被改过，可在配置里填
`client.version: "12.0.7"` / `client.build: 70500` —— 这两个字段只用于展示和 `when` 过滤。

**CASC 按 FileDataID 读模型**时，需要一条在自己的 exe 上唯一匹配的特征。用 `wowmod adapt`
从邻近 12.x 的特征自动推导，而不是手工找偏移：

```bash
wowmod adapt --config wowmod.json \
  --exe "D:/Games/WoW/Wow.exe" \
  --pattern "48 89 5C 24 08 57 48 83 EC 20 48 8B ?? ..." \
  --out hooks/patterns.adapted.json --name "wow-12.0.7"

wowmod scan --exe "D:/Games/WoW/Wow.exe" --patterns hooks/patterns.adapted.json
wowmod plan --config wowmod.json          # hook 模式应变成 fileid
wowmod launch --config wowmod.json
```

`adapt` 的算法：在可执行节区里做一次"最多差 N 个固定字节"的近似扫描，记录每个候选
具体是哪几个字节不同；把差异集合改成 `??` 后若只有它自己能匹配，就得到**最紧**的特征
（尽量少放宽）。差异太多（超过原固定字节三分之一）会明确给 ⚠，提示起点特征跨版本太远。

没有合适的特征也完全可用：保持 `allowFallback: true`，加载器自动用通用 VFS 层，
路径型覆盖（模型松散文件、AddOns、`Config.wtf`、MPQ 时代客户端）全部生效。

> 大多数情况你**不需要读这份文档**：把文件按游戏内路径放进模组目录、给一份 listfile，
> `wowmod plan` 就能工作（通用 VFS 层）。
> 只有当你的客户端是 CASC、按 FileDataID 从归档读模型，且 `plan` 显示 `mode = vfs` 时，才需要下面的第 3 步。

## 判断当前状态

```bash
wowmod plan --config wowmod.json
```

```
hook 模式: vfs — 没有任何特征能唯一匹配这个客户端；已退化为纯 VFS 覆盖 ...
hook 模式: fileid — 通过实际二进制能力探测选中 hook 点: my-server-3.3.5
```

`vfs` 不是错误，客户端照常启动。想让按 ID 读取的文件也生效，加一条特征。

## -1. 加密壳客户端：必须用运行时内存扫描（12.0.7 Firestorm 实测）

`WoW 12.0.7 - Firestorm.exe` 的导入表**只有 `Wow_loader.dll` 的一个 ordinal** —— exe 是启动壳。
但上传 DLL 后查明，比"扫 DLL"更根本：

| 文件 | `.text` 熵 | 说明 |
| --- | --- | --- |
| exe | 7.95–8.00 / 8 | **磁盘上是密文/压缩数据**，运行时解密；明文字符串只在 `.rdata` |
| `wow_loader.dll` | 6.23–7.23 | 真实代码，但游戏字符串被剥光 |

对两者跑 `discover` 都是 `xrefCount=0`，这是正确结论而非工具失败：**磁盘上不存在
指向明文字符串的 RIP 相对引用**。解决办法是扫进程运行时解密后的内存：

```bash
# 1) 在 Windows 上按 examples/12.0.7/wowmod.firestorm.json 启动一次
#    （hooks.runtimeScan=true, runtimeDump="runtime-dumps"）
#    → 生成 runtime-dumps/main.exe.img、wow_loader.dll.img、*.candidates.json

# 2) 离线分析内存映像（--mapped = 文件偏移等于 RVA）
wowmod discover --exe runtime-dumps/main.exe.img --mapped \
                --emit hooks/patterns.runtime.json --module ""
wowmod scan --exe runtime-dumps/main.exe.img --mapped \
            --patterns hooks/patterns.runtime.json
```

`PeImage(mapped=true)` 会把节区的 `raw_ptr` 设成 `rva`，否则会按磁盘 PE 的
`PointerToRawData` 读错位置。`--module` 决定断点加在哪个模块；空串是主 exe。

配置里加 `"hooks": {"scanTargets": ["Wow_loader.dll"]}`，`plan` 会同时扫描主 exe 与 DLL；
特征命中 DLL 时 Windows 注入层用 `GetModuleHandleW(L"Wow_loader.dll") + rva` 下断点。
`runtimeAutoInstall` 默认 `false`：候选仍需调试器确认 ID 寄存器与返回值语义。

**只有非加密客户端**才适用下面第 0 节的静态 `discover`；对本客户端请直接跳到内存扫描。

## 0. 先试试「零上传」的本地自动发现

如果你手上一个参考特征都没有，也不想上传 exe 给任何人：

```bash
wowmod discover --exe "D:/Games/WoW/Wow.exe" --anchors "DBFilesClient\\,Interface\\AddOns\\" \
                --emit hooks/patterns.discovered.json
wowmod scan --exe "D:/Games/WoW/Wow.exe" --patterns hooks/patterns.discovered.json
```

它在**你自己的机器**上完成：加载 PE → 在可执行节区找指向锚点字符串的 RIP 相对
`LEA reg,[rip+disp32]` → 把 rel32/disp32 与跳转立即数通配成 `??` → 用
`count_matches` 标出哪些候选是唯一匹配 → 输出可直接粘进 `patterns.json` 的特征。
`--anchors` 可换成你自己的字符串（例如某个模型路径），默认锚点见
`default_anchors()`（`DBFilesClient\`、`Interface\AddOns\`、`World\Model\`、
`realmlist.wtf`、`FileDataID`、`CascOpen` 等）。

**它是启发式候选，不是保证**：唯一匹配只说明字节序列唯一，不说明该函数就是
「按 FileDataID 打开、返回路径指针」。候选数量多时用 `wowmod scan` 收窄，
首次进游戏前用调试器核实。真正确定了函数入口后，再用下面的第 1~3 步写出正式特征。

## 1. 找 hook 点

目标是客户端里"**按 FileDataID 打开文件**"的函数入口：它的返回值是一个指向 null 结尾 ANSI 路径的指针
（客户端拿到路径后会去打开松散文件）。这正是 Arctium 系 launcher 用 `CustomFileIdHook` 打补丁的位置，
公开实现里那个函数的典型 prologue 是：

```
48 89 5C 24 08    mov [rsp+8], rbx
57                 push rdi
48 83 EC 20        sub rsp, 20h
48 8B ??           mov ...
...
```

用 x64dbg / IDA / Ghidra 在你的 `Wow.exe`（或 `WowClassic.exe`）里定位它，常用线索：

- 搜索 listfile 里的路径字符串引用，例如 `DBFilesClient\`、`Interface\`、`World\`；
- 搜索 `"Unable to open"` / `"file not found"` 一类错误信息，回溯到调用者；
- 在 `CascOpenFile` / `CascReadFile` 相关的内部封装上下断点，观察参数里的 FileDataID；
- 参考同版本号家族的公开 pattern 作为起点（不同 build 会有 1~2 字节差异）。

记下三件事：
- 函数入口的字节序列（含通配符 `??`）
- FileDataID 放在哪个寄存器（x64 常见 `edx`/`rdx`，也可能是 `ecx`/`r8d`）
- 架构（x64 / x86）

## 2. 写成数据

`hooks/patterns.json`：

```jsonc
{
  "patterns": [
    {
      "name": "my-private-3.3.5a",
      "kind": "fileId",
      "arch": "x64",
      // IDA 风格：?? = 通配符；也支持 "str:\"some string\"" 展开为 ASCII
      "pattern": "48 89 5C 24 08 57 48 83 EC 20 48 8B ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 74 ??",
      "offset": 0,                // 相对匹配起点的 hook 地址偏移
      "idRegister": "rdx",        // 存放 FileDataID 的寄存器
      "result": "rax=pathPtr",    // 返回值语义
      "priority": 10,
      "storage": ["casc"],        // 可选：只在 CASC 客户端启用
      "when": {},                 // 可选：builds / minBuild / maxBuild / products / arch
      "note": "我的私服 3.3.5a x64"
    }
  ]
}
```

可登记任意多条：加载器逐条在**你的实际 exe** 上扫描，只有**唯一匹配**且架构/过滤条件符合的才会启用；
多条命中时按 `priority` 与特征长度选最优的一条。

### 支持的寄存器名

`rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15`（x86 构建可用 `eax ecx edx ...`）。
`result` 目前固定 `rax=pathPtr`（x86 为 `eax`）：把 ANSI 路径指针放进返回寄存器并 `ret`。

## 3. 验证唯一性

```bash
wowmod scan --exe "D:/Games/WoW/Wow.exe" --patterns hooks/patterns.json
wowmod scan --exe "D:/Games/WoW/Wow.exe" --patterns hooks/patterns.json --json
```

```
[唯一]   my-private-3.3.5a -> 1 处 0x1a4c20(rva 0x1a5e20)
[无匹配] other-pattern -> 0 处
[多匹配] too-generic -> 7 处   ← 这条会被自动跳过，避免误 hook
```

**特征必须唯一**。太短的特征容易多处匹配，请增加固定字节。
`wowmod plan --json` 的 `hooks.matches[]` 会告诉你最终选了哪条、RVA 是多少。

## 4. 直接看效果

```bash
wowmod plan --config wowmod.json
wowmod launch --config wowmod.json
```

注入的 DLL 会在 `客户端基址 + RVA` 上设置 Dr0 硬件断点，用 VEH 短路返回模组文件路径。
日志 `wowmod.log` 里有完整的覆盖表与 hook 选择原因。

> 找不到合适的特征？把 `hooks.mode` 设为 `vfs` 即可明确只用通用层，
> 或保持 `auto` + `allowFallback: true`（默认）—— 找不到就自动降级，不会阻止进游戏。

## 常见失败原因

| 现象 | 原因 / 处理 |
|---|---|
| `scan` 显示 0 处 | 特征取自别的 build；按上面第 1 步重新定位 |
| `scan` 显示多处 | 特征太短，补 4~8 个固定字节 |
| `fileid` 模式但模型没变 | `idRegister` 填错；用调试器观察函数入口处 ID 在哪个寄存器 |
| `m.rva == 0` | 特征落在 PE 节区之外（匹配到了数据），把特征改到 `.text` |
| 客户端是 ARM64 | 硬件断点适配器暂不支持，会退回 VFS（x86/x64 正常） |
| 极早期加载的资源没替换 | 新线程的断点由 200ms 轮询补装；把模组改成按路径覆盖可避开 |

## 关于"适配任何版本"

这里的设计目标是：**加一个新版本永远不需要改 C++ 代码、不需要重新编译、不需要等作者发版**。
版本相关的信息全部是外部数据（listfile + patterns.json）。这是与"内置版本表"最本质的区别。
如果用户连特征都不想找，通用 VFS 层依然可用 —— 加载器不会因为版本未知而拒绝启动。
