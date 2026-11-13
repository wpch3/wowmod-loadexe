# WoW 12.0.7 专用起始包

> **真实客户端已上传并验证**：`WoW 12.0.7 - Firestorm.exe` = `12.0.7.68974` / x64 PE32+，
> 路径 `D:\Midnight Open Beta\_midnight_\`。exe 与 `wow_loader.dll` 均已上传并验证，
> 按真实路径填好的配置见 [`wowmod.firestorm.json`](wowmod.firestorm.json)，
> 完整清单/结论见 [`UPLOAD-CHECKLIST.md`](UPLOAD-CHECKLIST.md)。
>
> ⚠ **DLL 已上传并验证**：两个文件的磁盘代码都无法静态定位 hook 点 ——
> exe 的 `.text` 是加密的（熵 8.00），`wow_loader.dll` 的字符串被剥光。
> 已改用**运行时内存扫描**（`hooks.runtimeScan`）：注入后等壳解密，转储内存映像并
> 自动产出候选特征。详见 [`UPLOAD-CHECKLIST.md`](UPLOAD-CHECKLIST.md) 与
> [`wowmod.firestorm.json`](wowmod.firestorm.json)。
> 还差**一次 Windows 真机启动**（回传 `runtime-dumps/`）或 x64dbg 断一次入口来定稿。

**能。** 这套配置本身就是给 12.0.7 准备的，但里面**没有任何版本号判断**：
把 `client.portal` 改成你的私服地址、把模型放进 `mods/models/`，就能直接跑。
换成 12.1.5 / 3.3.5 / 1.12.1 也一样，不需要换加载器。

## 1. 放置

把这个目录里的文件复制到游戏根目录（`Wow.exe` 所在目录），或者保持目录结构，
用 `--config` 指向这里的 `wowmod.json`（相对路径都相对配置文件解析）。

改 `wowmod.json` 里的：

```jsonc
"client": {
  "exe": "",                  // 留空会自动找 wow*.exe；也可填绝对路径
  "portal": "127.0.0.1"      // ← 改成你的私服地址
}
```

## 2. 放模型 / 给 listfile

```
mods/models/World/Model/.../Dragon.m2        ← 按游戏内路径放
mappings/listfile.txt                        ← 换成 12.0.7 的 fileId;filePath 表
```

listfile 来源：<https://github.com/wowdev/wow-listfile>。
有了它，按路径摆放的模组会自动获得 FileDataID。

## 3. 直接看结果（这一步就能证明"已支持"）

```bash
wowmod detect   --config wowmod.json
wowmod validate --config wowmod.json
wowmod plan     --config wowmod.json
```

`detect` 会显示 `12.0.7`（若 `.build.info` 有完整 build 号则显示完整版本）、`x64`、`casc`，
以及 **支持状态: 已支持（无版本白名单）**。
`plan` 里的路径型覆盖（模型、材质、AddOns、`Config.wtf`）**立刻生效，与版本无关**。

> 如果你的 exe 版本资源被改过、读不到版本号，可在配置里填
> `client.version: "12.0.7"` 和 `client.build: 70500`（换成你的真实值）。
> 这两个字段**只影响展示与 `when` 过滤**，不是支持性判断。

## 4. 让 CASC「按 FileDataID 读取」的模型也生效（可选）

12.0.7 是 CASC 客户端，内部按 ID 从归档读文件，不会为每个模型调 `CreateFileW`。
这一步需要一个 hook 点（特征），但它**是数据、不是代码**：

```bash
# 方式 A：拿邻近 12.x 的特征当起点，让工具自动放宽成你这个 exe 上唯一匹配的版本
wowmod adapt --config wowmod.json \
  --exe "D:/Games/WoW/Wow.exe" \
  --pattern "48 89 5C 24 08 57 48 83 EC 20 48 8B ?? ..." \
  --out hooks/patterns.adapted.json \
  --name "wow-12.0.7"

# 方式 B：从仓库自带的参考特征文件开始（9.x/10.x 起点，跨大版本可能需要你提供更贴近 12.x 的特征）
wowmod adapt --config wowmod.json --exe "D:/Games/WoW/Wow.exe" \
  --from hooks/known-patterns.json --out hooks/patterns.adapted.json
```

`hooks/patterns.adapted.json` 已经在 `wowmod.json` 的 `patterns` 数组里，生成后直接：

```bash
wowmod scan --exe "D:/Games/WoW/Wow.exe" --patterns hooks/patterns.adapted.json
wowmod plan --config wowmod.json      # 期望看到 hook 模式: fileid
wowmod launch --config wowmod.json    # Windows
```

`adapt` 会优先用**差异引导**找最小的通配集合（只把跨版本真正变了的字节改成 `??`），
保证结果仍然唯一匹配、并落在可执行节区。若原始特征在你 exe 上 0 处匹配，
它会明确给出 ⚠ 警告 —— 唯一匹配不等于函数语义正确，请按 `docs/ADAPTING.md` 用调试器核实。

找不到特征也**不影响启动**：保持 `allowFallback: true`，加载器自动用通用 VFS 层。

## 5. 还差什么？一次 Windows 真机运行

**不用上传任何模组软件**（模型包、Arctium App 之类都是数据/UI，机制已在加载器里实现），
exe、分卷、`wow_loader.dll` 也**都已上传并验证完毕**。

但静态扫描对这个客户端不成立（磁盘 `.text` 是密文）。最后一步只能在 Windows 上跑：

```bash
# 1) 按真实路径启动，让 hooks.runtimeScan 转储解密后的内存
wowmod launch --config wowmod.firestorm.json
#    → runtime-dumps/main.exe.img、wow_loader.dll.img、*.candidates.json

# 2) 离线确认候选（可在我这边做，也可你自己做）
wowmod discover --exe runtime-dumps/main.exe.img --mapped --emit hooks/patterns.runtime.json
wowmod scan     --exe runtime-dumps/main.exe.img --mapped --patterns hooks/patterns.runtime.json
wowmod plan     --config wowmod.firestorm.json
```

`--mapped` 让加载器按「文件偏移 == RVA」解析内存映像；此时明文字符串与 RIP 相对
引用才真正存在。把 `runtime-dumps/` 发给我即可由我定稿特征。

或者更快：用 x64dbg 在解密后的 `LoadByFileId` / `CustomFileIdHook` 入口断一次，
给我前 24 字节 + ID 所在寄存器。

`discover --mapped` 会在内存映像的可执行节区里扫描指向 `DBFilesClient\`、
`Interface\AddOns\` 等字符串的 RIP 相对 LEA，生成候选特征并标出是否唯一匹配。
也可以用 `--anchors "你的字符串"` 换成你自己模组里的路径。

可选但有用的小文件：`.build.info`（Product/Branch/CDN Key）、`Data` 目录树列表、
12.0.7 listfile、私服 portal 地址。**请勿上传账号、登录器或反作弊相关文件。**

⚠ `discover` 给的是**候选**：唯一匹配不等于函数语义正确，首次进游戏前请用调试器或
`wowmod.log` 确认该点确实是「按 FileDataID 打开」的入口。

---

完整原理见 [docs/ADAPTING.md](../../docs/ADAPTING.md) 与 [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md)。
