# WoW 12.0.7 专用起始包

> **真实客户端已上传并验证**：`WoW 12.0.7 - Firestorm.exe` = `12.0.7.68974` / x64 PE32+，
> 路径 `D:\Midnight Open Beta\_midnight_\`。按真实路径填好的配置见
> [`wowmod.firestorm.json`](wowmod.firestorm.json)，还缺哪些文件见
> [`UPLOAD-CHECKLIST.md`](UPLOAD-CHECKLIST.md)。
>
> ⚠ 该 exe 是启动壳（导入表里只有 `Wow_loader.dll` ordinal #1），真正的游戏代码在那个
> 38 MB DLL 里。**请上传 `wow_loader.dll`** —— 有了它才能定位 CASC 的 FileDataID hook 点。

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

## 5. 需要上传东西吗？不需要

**不用上传任何模组软件**（模型包、Arctium App 之类都是数据/UI，机制已在加载器里实现）。
第 4 步缺的只有「你的 12.0.7 exe 自身的字节」，而这也**不必上传给我** —— 两条命令全在你本机跑：

```bash
# 没有任何参考特征时：自动从字符串引用找候选 hook 点
wowmod discover --exe "D:/Games/WoW/Wow.exe" --emit hooks/patterns.discovered.json

# 有邻近 12.x 特征时：自动放宽成唯一匹配
wowmod adapt --exe "D:/Games/WoW/Wow.exe" --pattern "..." --out hooks/patterns.adapted.json

wowmod scan --exe "D:/Games/WoW/Wow.exe" --patterns hooks/patterns.discovered.json
wowmod plan --config wowmod.json
```

`discover` 会在可执行节区里扫描指向 `DBFilesClient\`、`Interface\AddOns\` 等字符串的
RIP 相对 LEA，生成候选特征并标出是否唯一匹配。也可以用 `--anchors "你的字符串"` 换成
你自己模组里的路径。

如果愿意让我代劳验证，发我任选其一即可：

1. `Wow.exe`（或 `.text` 段片段）→ 我直接生成并验证特征；
2. 同家族（12.1.x）的 `CustomFileIdHook` / `LoadByFileId` 特征；
3. x64dbg 断下的前 24 字节 + ID 所在寄存器。

⚠ `discover` 给的是**候选**：唯一匹配不等于函数语义正确，首次进游戏前请用调试器或
`wowmod.log` 确认该点确实是「按 FileDataID 打开」的入口。

---

完整原理见 [docs/ADAPTING.md](../../docs/ADAPTING.md) 与 [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md)。
