# 限制、风险与使用边界

## "适配任何版本"的准确含义

- ✅ 加载器**不会因为版本未知而拒绝启动**；没有 `supported versions` 表，`supported` 恒为 `true`。
- ✅ 通用 VFS 覆盖层（第 1 层）与版本完全无关，任何 Windows 客户端都能用。
- ✅ 版本号只用于展示与用户自定义的模组过滤条件。
- ⚠️ CASC 客户端"按 FileDataID 从归档读取"的文件，需要第 2 层的 hook 点；hook 点来自外部
  `patterns.json` 的特征数据。**没有特征时这部分文件不会被替换**，但加载器仍会启动并应用所有路径型覆盖。
  这不是版本白名单 —— 加一条数据即可，不需要改代码或重新编译。见 [ADAPTING.md](ADAPTING.md)。

## 技术限制

| 限制 | 影响 | 缓解 |
|---|---|---|
| `fileid` 适配器仅 x86/x64 | ARM64 客户端退回 VFS | 用路径型覆盖；或后续扩展 CONTEXT 处理 |
| 每线程只用 Dr0，新线程靠 200ms 轮询补装 | 极早期加载的资源可能漏 | 让启动早期资源走路径覆盖；可缩短轮询 |
| `NtQueryDirectoryFile` 未 hook | 用原生 NT 目录枚举的客户端看不到**新增**文件 | 替换已有文件不受影响；新增 AddOns 走 `FindFirstFileW/ExW` |
| 动态 `GetProcAddress` 取得的函数指针绕过 IAT | 少数模块的文件调用不被拦截 | 已 hook `LoadLibraryW/ExW` 给新模块补装；必要时可扩展 EAT hook |
| 特征必须**唯一匹配** | 太短的特征被跳过 | 用 `wowmod scan` 验证，补固定字节 |
| `wowmod discover` / `adapt` 是启发式 | 唯一匹配不等于函数语义正确 | 首次进游戏前用调试器 / `wowmod.log` 核实该函数返回值是路径指针 |
| 加密壳客户端（12.0.7 Firestorm：exe `.text` 熵 8.00，DLL 字符串被剥光） | 磁盘文件里没有可引用的明文代码，静态 `discover` 必然 0 候选 | `hooks.runtimeScan` 转储解密后的内存映像，再用 `discover/scan --mapped` 分析；需一次 Windows 真机启动 |
| 运行时内存候选仍是启发式 | 唯一匹配不等于函数语义正确，默认不自动下断点 | 回传 `runtime-dumps/` 或用 x64dbg 确认「ID 寄存器 + 返回路径指针」后再设 `runtimeAutoInstall` |
| 描述符的 `idRegister`/`result` 需要人工确认 | 填错则按 ID 覆盖不生效 | 调试器观察函数入口；数据与代码分离，改 JSON 即可 |
| 生成文件落在 `%TEMP%/wowmod-<pid>/` | 会在临时目录留下小文件 | 不污染游戏目录；可手动清理 |
| Windows 注入未确认适用于所有加壳客户端 | 远程线程/APC/Windows hook 可能失败；错误码 0 不能直接证明反注入 | 失败时默认恢复客户端继续运行，并明确提示模组覆盖未加载；优先使用客户端正式支持的插件/覆盖入口 |

## 已知不做的事

- 不改写、不签名、不破解客户端 exe（除硬件断点外不触碰客户端代码）
- 不提供 CASC/TACT 清单重写或 CDN 伪装（那是另一条完全不同的路线）
- 不处理游戏的加密 / 认证 / 网络协议；portal 只是内存覆盖 `Config.wtf`
- 不支持 macOS 客户端
- 不内置任何 listfile 或特征库，避免"内置版本表"重新出现

## 合法与道德边界

**本项目只面向你自己搭建/参与的私服、离线 modding 与学习研究。**

- 不要在官方服务器上使用，会违反服务条款并导致封号。
- 只对你有权利修改的客户端与内容使用。
- 模型/材质等游戏资源版权归原权利人所有；本仓库的示例文件都是纯文本占位符。
- 本项目与 Blizzard / Arctium 无关联；文中提到它们仅为说明技术差异。

## 调试

- `wowmod plan` / `--json`：看最终覆盖表、冲突、hook 选择原因
- `wowmod scan`：验证特征是否唯一匹配
- `wowmod.log`（注入端生成）：客户端版本、覆盖表、诊断
- `OutputDebugStringA("[wowmod] ...")`：运行时 hook 命中计数（用 DebugView / 调试器查看）
- 导出函数：`wowmod_version` / `wowmod_overlay_count` / `wowmod_client_build` / `wowmod_hook_mode`
  可用于确认 DLL 确实注入且初始化成功
