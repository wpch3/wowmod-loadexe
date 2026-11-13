# 旧版 hook 特征适配说明（不代表 12.0.7 已支持）

> 本文原先记录通用 VFS / `hooks/patterns.json` 的静态扫描和硬件断点流程。它不是当前 Arctium 风格运行时加载器的实现说明，`detect` 中“不按 build 拒绝”也不等于资源替换能力已支持或验证。

当前 Firestorm 12.0.7 状态和 Arctium 参考实现见 [`ARCTIUM-STYLE.md`](ARCTIUM-STYLE.md)。映射预检命令是：

```sh
wowmod arctium-plan --config examples/12.0.7/wowmod.firestorm.json
```

该命令会验证 89 条路径到 FileDataID 的 loose-file 输入表，但不启动客户端、不安装 hook、不证明 CASC 读取或游戏内覆盖。

要将旧 `patterns.json`/硬件断点路线继续用于其他客户端，请先独立核实目标函数语义、ID 参数寄存器/宽度、返回值、指令边界及版本签名；唯一匹配本身不构成 ABI 证据。Firestorm 的运行时资料需求详见 [`examples/12.0.7/README.md`](../examples/12.0.7/README.md)。
