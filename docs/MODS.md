# 模组包 / 映射 / 规则

## 目录结构

```
my-server/
├── wowmod.json
├── Wow.exe                    ← 客户端（自动发现 wow*.exe）
├── .build.info                ← 可选，用于版本展示
├── WTF/Config.wtf
├── mods/
│   ├── dragon/                ← 一个模组包
│   │   ├── World/Model/Example/Dragon.m2
│   │   └── World/Textures/Example/Skin.blp
│   ├── ui/
│   │   └── Interface/AddOns/MyAddon/MyAddon.toc
│   └── hd/
│       ├── wowmod.manifest.json
│       └── override.blp
├── mappings/
│   └── listfile.txt
└── hooks/
    └── patterns.json
```

**模组包里的相对路径就是游戏内路径**。分隔符 `/` 或 `\` 都行，大小写不敏感。

## 自动获得 FileDataID

`mappings/listfile.txt`（格式来自 [wowdev/wow-listfile](https://github.com/wowdev/wow-listfile)）：

```
# fileId;filePath
123456;World/Model/Example/Dragon.m2
123457;World/Textures/Example/Skin.blp
```

扫描模组目录时，每个文件都会查这张表；命中就同时登记路径覆盖和 FileDataID 覆盖。
**换客户端版本只需要换这张表**，加载器里没有任何 ID 表。

支持：
- `;` 后有多余字段（忽略）
- `#` / `;` 开头的注释行
- `0x` 前缀的 ID
- UTF-8 BOM、CRLF、路径两端引号

## 显式清单 `wowmod.manifest.json`

放在模组包根目录（或在配置里用 `manifest` 指定）：

```json
{
  "files": [
    { "id": 123457, "file": "override.blp" },
    { "path": "World/Model/Example/Dragon.m2", "file": "alt-dragon.m2" }
  ]
}
```

- 只给 `id`：会先用 listfile 反查真实游戏路径作为 key，查不到才用 `#id` 占位
- 只给 `path`：直接登记该路径，并自动查 ID
- 清单引用的本地文件不会再被当成普通路径文件登记（不会产生 `override.blp` 这种噪声覆盖项）
- 清单条目的优先级 = 模组包 `priority + 1`

## 优先级 / 冲突

```jsonc
{ "name": "B", "path": "mods/b", "priority": 30, "enabled": true }
```

- 数字越大越优先
- 优先级相同 → **配置里靠后的包**优先
- `rules` 默认优先级 1000（高于普通模组），`replace` 为空表示屏蔽该文件
- 内存生成的 `WTF/Config.wtf` 优先级 10000

`wowmod plan` 只展示**裁决后的最终覆盖表**；诊断里会提示发生了多少处冲突。

## 适用范围（可选过滤器）

```jsonc
"when": {
  "minBuild": 9000,
  "maxBuild": 40000,
  "builds": [12340, 70783],
  "products": ["wow_classic"],
  "storage": ["casc"],
  "arch": ["x64"]
}
```

全部留空 = 任何版本都生效。这只是**给用户限定模组生效范围**的工具，
不是加载器的"支持版本列表"：过滤器不匹配只会跳过该模组，客户端照常启动。

## 规则

```jsonc
"rules": [
  { "match": "World/**/*.m2", "replace": "mods/fallback/Generic.m2" },
  { "match": "Interface/AddOns/OldAddon/*", "replace": "" }
]
```

- `*` / `**` / `?` 通配符，大小写不敏感，匹配的是规范化后的 game-relative 路径
- `replace` 为空 → 屏蔽（客户端打开该路径会得到"文件不存在"）
- 规则也可以带 `when` 和 `priority`

## 内存生成文件（不改磁盘）

| 配置项 | 生成的文件 | 行为 |
|---|---|---|
| `client.portal` | `WTF/Config.wtf` | 保留原内容，替换或追加 `SET portal "<值>"` |
| `client.realmlist` | `realmlist.wtf` / `Data/.../realmlist.wtf` | 追加 `set realmlist <值>` |

生成物写到 `%TEMP%/wowmod-<pid>/`，覆盖层把它挂到游戏目录的对应路径上。
`wowmod plan --materialize DIR` 可以把它们导出来检查。

## 覆盖能力一览

| 场景 | 是否生效 | 说明 |
|---|---|---|
| 替换已有松散文件 / AddOns / 配置 | ✅ 所有版本 | 通用 VFS 层 |
| 新增 AddOns 目录 | ✅ 所有版本 | `FindFirstFileW/ExW` 目录枚举叠加 |
| MPQ 时代客户端的模型/材质 | ✅ 所有版本 | 按路径覆盖（客户端若只读归档需配合补丁 exe / 特征） |
| CASC 按 FileDataID 读取的模型 | ✅ 需 `mode=fileid` | 见 [ADAPTING.md](ADAPTING.md) |
| 屏蔽某个文件 | ✅ 所有版本 | `rules` 或 IAT 层返回"不存在" |
| 修改磁盘上的游戏文件 | ❌ 永不 | 设计原则 |
