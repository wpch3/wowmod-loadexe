# Blood Elf Female HD 纹理包

本目录包含从素材提交导入的 89 个 `.blp` 文件，按游戏相对路径放置。它是纹理替换包，不含 `.m2` 几何模型。

对应映射位于 `examples/12.0.7/mappings/listfile.txt`。从仓库根目录执行：

```sh
wowmod arctium-plan --config examples/12.0.7/wowmod.firestorm.json
```

当前命令只验证 loose-file 路径和 FileDataID 映射，不启动、注入或修改客户端；不能证明 Firestorm 12.0.7 的资源替换已生效。运行时 hook 和游戏内验证状态见 `examples/12.0.7/README.md` 与 `docs/ARCTIUM-STYLE.md`。
