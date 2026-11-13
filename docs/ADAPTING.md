# 为任意私服 build 适配

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
