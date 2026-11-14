// 零模块初始化：在目标进程的【主线程】之外抢先跑一段我们自己写的机器码，
// 全程不出现任何 DLL 模块。
//
// 为什么必须这么做：
//   Firestorm 客户端会扫描模块表，发现陌生 DLL 就报
//     错误 0x1100 「检测到不受支持的软件」并点名该 DLL，
//   随后 0xC00000E5 (EXCEPTION_INTERNAL_ERROR) 崩溃。
//   这不是我们能"绕过"的兼容性问题，而是设计如此的完整性检查。
//   所以任何 LoadLibrary / 手工映射进模块表 / 带 PE 头的映像都会被拒。
//
// 我们的做法（等价于 Arctium 的"启动器在进程里干活"，只是不需要 DLL）：
//   1. 正常启动客户端（不挂起，让加载器完成初始化）；
//   2. VirtualAllocEx 一块【没有 PE 头】的可执行内存，写入一段位置无关的机器码；
//   3. CreateRemoteThread 执行它；
//   4. 这段机器码在进程里循环等待一个"命令标志"，启动器通过
//      ReadProcessMemory / WriteProcessMemory 与它通信 —— 也就是把目标进程
//      当成一台可以远程读写内存的机器，所有分析结果通过共享缓冲区取回。
//
// 优点：模块表里永远不会出现陌生条目，0x1100 不会触发。
// 代价：跨进程通信必须自己设计（本文件里的 SharedRegion 就是这套协议）。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace wowmod {
namespace win {

// 启动器与目标进程内代理之间共享的控制块。
// 全部字段都是固定宽度、自然对齐，双方直接按偏移读写。
struct AgentControl {
  uint32_t magic;        // 写入后表示"控制块已就绪"
  uint32_t command;      // 启动器写：要代理做什么
  uint64_t arg0;         // 命令参数
  uint64_t arg1;
  uint64_t result0;      // 代理写回
  uint64_t result1;
  uint64_t status;       // 0=空闲 1=执行中 2=完成 3=出错
  uint64_t heartbeat;    // 代理每次循环自增，用来确认它还活着
};

// ---- 控制块字段偏移 ----
// 这些偏移同时被宿主侧（C++）和远端机器码（硬编码立即数）使用。
// 一旦结构体布局变化而机器码没跟着改，代理就会读写错位置 ——
// 心跳会是 0、命令永远不生效。所以这里用 static_assert 锁死，
// 让编译器在偏移漂移时直接报错，而不是等到运行时"没有心跳"。
static constexpr uint32_t kAgentMagic = 0x574D4147u;  // 'WMAG'

constexpr size_t kOffMagic     = offsetof(AgentControl, magic);
constexpr size_t kOffCommand   = offsetof(AgentControl, command);
constexpr size_t kOffArg0      = offsetof(AgentControl, arg0);
constexpr size_t kOffArg1      = offsetof(AgentControl, arg1);
constexpr size_t kOffResult0   = offsetof(AgentControl, result0);
constexpr size_t kOffResult1   = offsetof(AgentControl, result1);
constexpr size_t kOffStatus    = offsetof(AgentControl, status);
constexpr size_t kOffHeartbeat = offsetof(AgentControl, heartbeat);
constexpr size_t kOffSleepPtr  = 56;   // 结构体之后紧跟 Sleep 指针
constexpr size_t kAgentCtlSize = 128;  // 控制块总大小

static_assert(kOffMagic == 0, "magic 必须在偏移 0");
static_assert(kOffCommand == 4, "command 必须在偏移 4（magic 是 uint32）");
static_assert(kOffArg0 == 8, "arg0 必须在偏移 8");
static_assert(kOffHeartbeat == 48, "heartbeat 必须在偏移 48");

enum AgentCommand : uint32_t {
  kAgentNoop = 0,
  kAgentPing = 1,
  kAgentCall = 2,       // arg0=函数地址 arg1=参数，调用后把 rax/rdx 写回
  kAgentWriteBytes = 3, // arg0=地址 arg1=缓冲区 VA（长度由 ctl 外部记录）
  kAgentQuit = 9,
};

// 目标进程里的"代理"句柄。
class RemoteAgent {
 public:
  RemoteAgent() = default;
  ~RemoteAgent() { detach(); }
  RemoteAgent(const RemoteAgent&) = delete;
  RemoteAgent& operator=(const RemoteAgent&) = delete;

  // 在目标进程里启动代理（写入机器码 + 起线程）。
  bool attach(HANDLE process, std::string* err);

  // 发一条命令并等待完成。
  bool command(uint32_t cmd, uint64_t a0, uint64_t a1, uint64_t* r0, uint64_t* r1,
               std::string* err, DWORD timeout_ms = 30000);

  // 在目标进程里调用一个函数（走代理，不新起线程）。
  bool call(uint64_t fn, uint64_t arg, uint64_t* ret, std::string* err);

  // 确认代理还活着。
  bool alive() const;

  void detach();

  uint64_t control_va() const { return ctl_va_; }
  uint64_t code_va() const { return code_va_; }
  const std::string& method() const { return method_; }

 private:
  HANDLE process_ = nullptr;
  uint64_t ctl_va_ = 0;
  uint64_t code_va_ = 0;
  uint64_t thread_handle_ = 0;
  std::string method_ = "远程代理（无模块）";
};

// 生成代理机器码。ctl_va 是控制块的绝对地址。
// 循环：读 ctl->command，处理，写回 result/status，自增 heartbeat。
std::vector<uint8_t> build_agent_code(uint64_t ctl_va);

}  // namespace win
}  // namespace wowmod
#endif
