# 已知限制（诚实清单）

最后更新：2026-11-13。只列**现在还成立**的限制，已解决的写进"已解决"。

## 尚缺（按重要性）

1. **FileDataID 的参数位置与返回语义未实测。**
   拦截模式（`--mode auto`）会在客户端里记录每个「加载本地文件」函数的
   `rax/rcx/rdx/r8/r9/rsp` 快照，但这份日志必须在真实 Firestorm 进程里产生一次。
   在这之前 `--mode hook` 只能靠 `WOWMOD_RT_IDREG` 手工指定，属于未验证配置。

2. **本仓库的 Windows 二进制从未在 Windows 上运行过。**
   构建环境是 Linux + zig 交叉编译，没有 wine、没有 Windows。四个 PE 的结构
   （导出表、导入表、无 CRT 缺失）已用 Python 逐项校验，但"双击能跑"必须由你在
   自己机器上确认。这是环境限制，不是代码已知缺陷。

3. **只在 SHA-256 已核对的那份 68974 构建上验证过分析路径。**
   分析器不写死任何 RVA/特征偏移，所以理论上换构建也能用，但换构建后
   detour 目标会变，必须重新跑 `--mode observe`。

4. **`--mode hook` 的安装路径没有端到端成功案例。**
   安装流程的每一步（分配、写入、保护位、序言分析、跳板生成、回填、回滚）
   都单独验证过（capstone + 单元测试），但"装上之后游戏里真的换贴图"从未观测到，
   原因见第 1 条。

## 明确不做

* 不改客户端 exe 文件本体（`.pdata`/cave 路线虽然有实现 `launcher_stub`，但
  需要修改磁盘 exe，且要过完整性校验，因此**不设为默认**，命令行也不暴露）。
* 不碰 CASC 存储写。`CascLib` 只有读接口（`CascReadFile` / `CascOpenStorageEx`），
  覆盖只能走"拦截文件打开"或"VFS 层"，这正是本项目选 hook 的原因。
* 不提供绕过反作弊/防篡改的手段。本项目的所有写操作都发生在
  **你自己启动的、你拥有权限的进程** 内。

## 已验证，不是限制（避免重复怀疑）

* 指令长度解码器与 capstone **100.0000%** 一致（2,015,814 条指令，
  gcc `.text` / libc / libstdc++ / libcrypto）。
* `find_safe_split` 不会切断指令；测试覆盖 14/16 字节两种边界。
* FileDataID 跳板（61 字节）逐条 capstone 验证，9 种 id 寄存器组合都能生成。
* 启动器前置跳板（85 字节）逐字节验证：`pushfq` + 14 push / 14 pop + `popfq`
  严格配平，跳回地址 = `stub_va + stub_len`（因为 cave 紧贴函数入口）。
* detour 安装器的 7 条失败路径全部回滚，不留半装状态。
* 324 项核心测试全绿。

## 历史上失败、已放弃的做法（不要重试）

* 向挂起进程远程 `LoadLibraryW` / `NtCreateThreadEx` / APC / `SetWindowsHookExW`
  —— 在这个客户端上全部被静默拒绝（后者直接 error 87）。
* 从 `firestorm-runtime-dumps.zip` 重建 PE 头 —— 导出区域不从模块基址开始，
  `main_image.bin` 无法用于节表重建。
* 从 28.4 MB 区域里抓 ASCII/特征码 —— 熵 0.63，无字符串，是压缩/加密数据。
* 用自写 x86 模拟器验证序言搬运 —— 不可靠，已改为 capstone + 真实编译产物。
