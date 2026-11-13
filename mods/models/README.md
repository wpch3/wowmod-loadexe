# 12.0.7 模型替换包

把替换文件按**游戏内路径**放在这个目录，例如：

```
mods/models/World/Model/Example/Dragon.m2
mods/models/Interface/AddOns/MyAddon/MyAddon.toc
```

也可以写 `wowmod.manifest.json` 直接按 FileDataID 指定：

```json
{ "files": [ { "id": 123456, "file": "Dragon.m2" } ] }
```

运行 `wowmod plan --config wowmod.json` 查看最终覆盖表。
