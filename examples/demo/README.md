# 演示目录

这个目录里除 `client/` 外都是真实文件，`client/` 由脚本生成的**合成 PE**（不是游戏）。

```bash
# 生成任意版本的"假客户端"
python3 ../../tools/make_fake_client.py --dir client --version 3.3.5.12340

# 探测 / 干跑 / 特征扫描
../../build/wowmod detect   --config wowmod.json
../../build/wowmod plan     --config wowmod.json
../../build/wowmod scan     --config wowmod.json
../../build/wowmod validate --config wowmod.json
```

换一个版本号再跑一遍（例如 `12.0.7`、`12.1.5.70783`、`1.12.1.5875`、`5.4.8.18414`）：
输出永远是「已支持」，覆盖表和 hook 选择照常工作 —— 这就是没有版本白名单的意思。

## 内容

```
wowmod.json                 演示配置（portal / 3 个模组包 / listfile / 特征）
mappings/listfile.txt       4 条 fileId;filePath
mods/dragon/                按路径覆盖（M2 + BLP）
mods/ui/                    按路径覆盖（新增 AddOns）
mods/hd/                    wowmod.manifest.json 按 FileDataID 覆盖（优先级 30，会盖过 dragon 的 BLP）
hooks/patterns.json         一条能唯一匹配合成客户端 .text 的特征
client/                     (生成物，已在 .gitignore)
```

`mods/hd` 的优先级比 `mods/dragon` 高，`plan` 会显示 `world/textures/example/skin.blp`
最终指向 `mods/hd/override.blp`，并提示有 1 处冲突被裁决。

## Web 控制台

```bash
node ../../web/server.js    # http://localhost:3000
```

左侧可以直接输入任意版本号重新生成合成客户端，右侧的覆盖表、诊断、特征匹配情况
都由真实的 `wowmod plan --json` / `scan --json` 计算得出（不是写死的 mock 数据）。
