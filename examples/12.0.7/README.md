# WoW 12.0.7 专用起始包

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

## 5. 我需要你提供什么才能把第 4 步做完

任选其一：

1. 你的 `Wow.exe`（或只发 `.text` 段的前若干 KB / 一个字节特征），我来生成并验证 12.0.7 的特征；
2. 你手上已有的、同家族（12.1.x）的 `CustomFileIdHook` / `LoadByFileId` 特征；
3. 用 x64dbg 在「按 FileDataID 打开」函数入口断下，把前 24 字节和 ID 所在寄存器告诉我。

只有第 3 项涉及人工定位；其余都只是数据转换，不需要改加载器代码。

---

完整原理见 [docs/ADAPTING.md](../../docs/ADAPTING.md) 与 [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md)。
