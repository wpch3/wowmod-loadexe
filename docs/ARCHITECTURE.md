# 架构与数据流

## 为什么现有 launcher 会"不支持你的版本"

以 Arctium 系 WoW-Launcher 为例（公开源码可查），它做三件与版本强绑定的事：

1. `GameVersion` 枚举 + `MajorGameVersion = {9, 10}`、`MinGameBuild = 37862` 之类的编译期常量；
2. `Patterns/Windows.cs` 里为 `LoadByFileId` / `CustomFileIdHook` 等内部函数写死 x64 字节特征，并按 10.0+ 切换"alternate pattern"；
3. 启动时按 `_retail_` / `_classic_` 等固定目录名找 exe。

任何一条不匹配 → 报"不支持"。私服 build、改过的客户端、旧版本、新版本都会被挡在外面。

## 本项目的处理

```
                 ┌──────────────────────────────────────────────┐
  磁盘上的数据 →  │  wowmod_core（可移植 C++17，无第三方依赖）    │
                 │                                              │
  .build.info    │  version.cpp   版本/架构/存储布局探测（只读）  │
  PE 版本资源    │  json.cpp      JSONC 解析                     │
  WTF/Config.wtf │  mapping.cpp   fileId;filePath 映射           │
  listfile.txt   │  config.cpp    配置模型 + 可选过滤器           │
  wowmod.json    │  vfs.cpp       覆盖表 / 冲突裁决 / 内存生成    │
  patterns.json  │  hooks.cpp     特征扫描 + 能力探测             │
  Wow.exe        │  pattern.cpp   IDA 风格通配符匹配              │
                 └───────────────┬──────────────────────────────┘
                                 │  (同一套核心，Linux/macOS/Windows 都能编译)
        ┌────────────────────────┴─────────────────────────┐
        │                                                  │
   wowmod.exe (CLI)                              wowmod_hook.dll (注入客户端)
   detect/validate/plan/scan/init                runtime.cpp   重建覆盖表、生成内存文件
   launch.cpp  CreateProcess(SUSPENDED)         iat_hook.cpp  遍历已加载模块 IAT
   inject.cpp  LoadLibraryW 远程线程            fs_hooks.cpp  文件 API detour
                                                fileid_hook.cpp  Dr0 + VEH 适配器
```

**关键不变量**：`wowmod_core` 里没有任何 `build == N`、没有硬编码偏移、没有内置特征表。
所有"版本知识"都是运行时读进来的**数据**。

## 启动时序（Windows）

```
wowmod launch
  │  1. detect_client()            读 .build.info / PE 版本资源 / Data 布局
  │  2. MappingTable.load_file()   读 listfile
  │  3. Vfs.build()                扫描模组目录 → 覆盖表（含优先级裁决）
  │  4. plan_hooks()               在真实 exe 字节上扫描 patterns.json
  │  5. SetEnvironmentVariable("WOWMOD_CONFIG", 配置绝对路径)
  │  6. CreateProcessW(..., CREATE_SUSPENDED)
  │  7. CreateRemoteThread(LoadLibraryW, "wowmod_hook.dll")
  │       └─ DllMain:
  │          a. init_runtime()     重复 1~4（进程内），materialize_generated()
  │          b. install_iat_hooks()  ← 从这里开始才拦截文件 API（避免自递归）
  │          c. install_fileid_hook()（仅当 plan.mode == "fileid"）
  │  8. ResumeThread(主线程)
```

注入在挂起阶段完成，因此覆盖层在客户端第一行游戏代码执行前就位。
若注入失败，`launch` 会 `TerminateProcess`，绝不让客户端在"没有覆盖层"的状态下运行。

## 覆盖表是怎么构建的

```
对每个启用的模组包（when.matches(client) 为真）:
  ├─ 递归扫描 pack.path/pack.root 下的文件
  │    key = 文件相对路径（小写、'/' 分隔）
  │    查 listfile → 若命中，同时登记 FileDataID
  ├─ 若存在 wowmod.manifest.json:
  │    { id, file }      → 用 listfile 反查路径作为 key，并登记 id
  │    { path, file }    → 直接登记 path（再查 id）
  └─ 清单引用的本地文件不再作为普通路径登记（避免噪声）

内存生成文件:
  WTF/Config.wtf  ← 保留原内容，替换/追加 SET portal
  realmlist.wtf   ← 老客户端

rules:
  在 resolve 时按通配符匹配，优先级 1000（默认），replace 为空 = 屏蔽

冲突:
  先比 priority，再比加载顺序；结果存在 by_path_ / by_id_ 两个索引里
```

`Vfs::effective_entries()` 返回裁决后的最终表，CLI 的 `plan` 与 Web 控制台都展示这一份。

## 路径请求的解析（`resolve_redirect`）

客户端可能用三种形式请求同一个文件：

```
D:\Games\WoW\World\Model\Dragon.m2                     DOS 绝对路径
\Device\HarddiskVolume3\Games\WoW\World\Model\Dragon.m2  NT 路径（NtCreateFile）
World\Model\Dragon.m2                                   相对路径
```

解析顺序：
1. 去掉已知前缀（游戏目录、exe 目录、其父目录）→ game-relative key
2. 否则若是相对路径 → 直接当 key
3. 否则（NT 设备路径等）→ 按**文件名索引**做后缀匹配 + 边界检查 + "看起来在游戏目录里"检查

命中后返回 `Replace(真实路径)` / `Block` / `None`。`CreateFile*` 接到 `Replace` 就换成模组文件；
`NtCreateFile` 会构造 `\??\D:\...` 形式的 `UNICODE_STRING` 再调用原函数。

## 为什么用 IAT hook 而不是内联补丁

| | 内联补丁 (mid-function detour) | IAT hook（本项目） |
|---|---|---|
| 依赖 | 目标函数前 12~15 字节、指令边界、重定位 | 只依赖 PE 导入表结构 |
| 版本变化 | 极易失效 / 崩溃 | 不受影响 |
| 需要的库 | MinHook/Detours + 反汇编长度解码 | 零依赖，~120 行 |

缺点是：如果某个模块通过 `GetProcAddress` 动态取函数指针再调用，IAT hook 覆盖不到。
为此本项目 hook `LoadLibraryW/ExW` 给运行时新加载的模块补装；实测主流客户端走 IAT。

## 为什么 FileDataID 适配器用硬件断点

CASC 的"按 ID 打开文件"是客户端内部函数，没有稳定的导出名。常规做法是在它入口打内联补丁
（Arctium 就是这么做的，因此每个版本要一条特征 + 一段汇编）。本项目的做法：

```
Dr0 = 客户端模块基址 + 特征匹配处的 RVA
Dr7 |= L0（本地执行断点）
AddVectoredExceptionHandler(1, veh_handler)

断点命中:
  id = CONTEXT[descriptor.idRegister]
  若 g_id_paths[id] 存在:
      RAX = 模组文件 ANSI 路径指针
      RIP = *RSP; RSP += 8        // 等价于 ret
      EFlags |= RF
      EXCEPTION_CONTINUE_EXECUTION
  否则:
      EFlags |= RF                // 让原始指令正常执行，不重复触发
```

优点：**客户端代码零修改**，特征失效最多是不生效，不会破坏堆栈或指令流。
描述符的 `idRegister` / `result` 是外部数据，不是编译期约定，所以换架构/换调用约定也能靠数据描述。

## 测试策略

`tests/tests.cpp` 是零依赖单元测试，在 Linux / macOS / Windows 上都能跑，覆盖：

- 路径规范化、glob、`fileId;filePath` 解析
- JSONC（注释 / 尾随逗号 / `\uXXXX` / 错误路径 / 往返）
- `.build.info` 解析、**自建合成 PE32+ 的版本资源与 RVA↔偏移换算**
- 配置加载与可选过滤器
- VFS：优先级冲突、manifest 按 ID、listfile 自动关联、内存生成 Config.wtf、规则屏蔽、目录枚举叠加
- 特征解析与扫描、唯一匹配选择、无特征时的安全退化

Windows 专属代码另外用 zig 交叉编译器做**编译 + 链接验证**（见 [BUILD.md](BUILD.md)），
CI 里再用 MSVC 真正构建 `wowmod.exe` 与 `wowmod_hook.dll`。
