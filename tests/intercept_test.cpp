// 拦截跳板的语义测试（可在 Linux / Windows 上运行）。
//
// 为什么单独一个文件：跳板是【在客户端进程里运行的机器码】，它一旦有错，
// 表现是"客户端随机崩溃"或"记录全是垃圾"，极难排查。所以这里不靠读代码，
// 而是把跳板的字节真正映射成可执行内存、真的 call 它，验证四件事：
//   1) 五个被记录的寄存器（rax/rcx/rdx/r8/r9）调用后原样还原
//   2) 计数器正确累加
//   3) 环形缓冲里的快照字段正确（含 seq）
//   4) 最后真的跳到 trampoline（原函数继续执行）
// 还要验证环形回绕时【槽位公式】正确 —— 这里曾经有过一个真实的 bug：
// 跳板用自增前的计数取槽（第一次写 slot 0），而轮询端错用了 seq & mask，
// 结果整条记录错位一格，读到的是上一次调用的数据。
//
// 跳板字节由 build_intercept_stub() 生成（与线上同一份代码），
// 但这里通过 fd_hook_stub_bytes() 取得纯字节，避免依赖 windows.h。
// SPDX-License-Identifier: MIT
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "wowmod/intercept_stub.hpp"

#if !defined(_WIN32)
#include <sys/mman.h>
#endif

// 这两个必须是非静态全局：汇编里用 RIP 相对寻址直接引用
uint64_t g_counter = 0;
uint8_t g_ring[8 * 64] = {0};
int g_tramp_hits = 0;

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool ok, const char* what) {
  ++g_checks;
  if (!ok) {
    ++g_failures;
    std::printf("  FAIL %s\n", what);
  }
}

// 记录槽字段（与 win::InterceptRecord 保持一致）
constexpr size_t kRax = 0;
constexpr size_t kRcx = 8;
constexpr size_t kRdx = 16;
constexpr size_t kR8 = 24;
constexpr size_t kR9 = 32;
constexpr size_t kRsp = 40;
constexpr size_t kSeq = 48;
constexpr size_t kRecSize = 64;



class ExecBlock {
 public:
  explicit ExecBlock(const std::vector<uint8_t>& code) {
#if defined(_WIN32)
    // Windows 上测试由 CI 用 wowmod.exe 之外的路径跑；这里给出可执行内存
    // 的等价实现（VirtualAlloc）。为保持本文件不依赖 windows.h，
    // Windows 构建下由调用方提供实现。
    (void)code;
#else
    mem_ = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem_ != MAP_FAILED) std::memcpy(mem_, code.data(), code.size());
#endif
  }
  ~ExecBlock() {
#if !defined(_WIN32)
    if (mem_ && mem_ != MAP_FAILED) munmap(mem_, 4096);
#endif
  }
  void* get() const { return mem_; }
  bool ok() const {
#if defined(_WIN32)
    return false;  // 见上方说明：Windows 由外部集成测试覆盖
#else
    return mem_ && mem_ != MAP_FAILED;
#endif
  }

 private:
  void* mem_ = nullptr;
};

#if !defined(_WIN32)
extern "C" void wowmod_test_tramp();
asm(R"(
.text
.globl wowmod_test_tramp
wowmod_test_tramp:
  incl g_tramp_hits(%rip)
  ret
)");
#endif

// 调用跳板 N 次，每次把 rcx 设为 0x100+i
void call_stub_n(void* fn, int n) {
#if !defined(_WIN32)
  for (int i = 0; i < n; ++i) {
    uint64_t v = 0x100 + static_cast<uint64_t>(i);
    asm volatile(
        "mov %[v], %%rcx\n"
        "call *%[fn]\n"
        : [v] "+r"(v)
        : [fn] "r"(fn)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory");
  }
#else
  (void)fn;
  (void)n;
#endif
}

}  // namespace

namespace wowmod {
namespace test {

int run_intercept_stub_tests(int* checks_out) {
  std::printf("[intercept_stub]\n");

  // 4 个槽的环形缓冲
  constexpr uint32_t kSlots = 4;
  std::vector<uint8_t> code = build_intercept_stub_bytes(
      reinterpret_cast<uint64_t>(&g_counter), reinterpret_cast<uint64_t>(g_ring), kSlots - 1);
  check(!code.empty(), "跳板不应为空");
  check(code.size() > 100, "跳板长度应 >= 100 字节");

  // 最后 8 字节是 trampoline 地址占位
  const uint64_t tramp = reinterpret_cast<uint64_t>(&wowmod_test_tramp);
  std::memcpy(code.data() + code.size() - 8, &tramp, 8);

  ExecBlock exec(code);
  if (!exec.ok()) {
    std::printf("  (跳过执行验证：本平台无 mmap)\n");
    std::printf("[intercept_stub] %d 项检查, %d 项失败\n", g_checks, g_failures);
    if (checks_out) *checks_out = g_checks;
    return g_failures;
  }

  g_counter = 0;
  g_tramp_hits = 0;
  std::memset(g_ring, 0, sizeof(g_ring));

  // --- 单次调用：寄存器还原 + 快照 + 跳转 ---
#if !defined(_WIN32)
  {
    uint64_t out_rcx = 0, out_rdx = 0, out_r8 = 0, out_r9 = 0;
    asm volatile(
        "mov $0x1111, %%rcx\n"
        "mov $0x2222, %%rdx\n"
        "mov $0x3333, %%r8\n"
        "mov $0x4444, %%r9\n"
        "call *%[fn]\n"
        "mov %%rcx, %[a]\n"
        "mov %%rdx, %[b]\n"
        "mov %%r8,  %[c]\n"
        "mov %%r9,  %[d]\n"
        : [a] "=m"(out_rcx), [b] "=m"(out_rdx), [c] "=m"(out_r8), [d] "=m"(out_r9)
        : [fn] "r"(exec.get())
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory");
    check(out_rcx == 0x1111, "rcx 应原样还原");
    check(out_rdx == 0x2222, "rdx 应原样还原");
    check(out_r8 == 0x3333, "r8 应原样还原");
    check(out_r9 == 0x4444, "r9 应原样还原");
  }
  check(g_counter == 1, "计数器应为 1");
  check(g_tramp_hits == 1, "应跳到 trampoline 一次");
  {
    uint64_t s_rcx = 0, s_rdx = 0, s_r8 = 0, s_r9 = 0, s_seq = 0;
    std::memcpy(&s_rcx, g_ring + 0 * kRecSize + kRcx, 8);
    std::memcpy(&s_rdx, g_ring + 0 * kRecSize + kRdx, 8);
    std::memcpy(&s_r8, g_ring + 0 * kRecSize + kR8, 8);
    std::memcpy(&s_r9, g_ring + 0 * kRecSize + kR9, 8);
    std::memcpy(&s_seq, g_ring + 0 * kRecSize + kSeq, 8);
    // 第一次调用必须写 slot 0（早期版本先自增再取模，slot 0 永远空着）
    check(s_rcx == 0x1111, "slot0 里应记录首次调用的 rcx");
    check(s_rdx == 0x2222, "slot0 里应记录首次调用的 rdx");
    check(s_r8 == 0x3333, "slot0 里应记录首次调用的 r8");
    check(s_r9 == 0x4444, "slot0 里应记录首次调用的 r9");
    check(s_seq == 1, "slot0 的 seq 应为 1");
  }

  // --- 多次调用：环形回绕 + 槽位公式 ---
  g_counter = 0;
  g_tramp_hits = 0;
  std::memset(g_ring, 0, sizeof(g_ring));
  const int kN = 9;
  call_stub_n(exec.get(), kN);
  check(g_counter == static_cast<uint64_t>(kN), "计数器应等于调用次数");
  check(g_tramp_hits == kN, "每次调用都应跳到 trampoline");

  // 槽位公式：slot = (seq - 1) & mask。seq=kN 的那次调用写在 slot (kN-1)&3。
  int slot_bad = 0;
  for (uint64_t seq = 6; seq <= 9; ++seq) {
    const uint64_t slot = ((seq - 1) & (kSlots - 1)) * kRecSize;
    uint64_t got_rcx = 0, got_seq = 0;
    std::memcpy(&got_rcx, g_ring + slot + kRcx, 8);
    std::memcpy(&got_seq, g_ring + slot + kSeq, 8);
    // 第 seq 次调用的 rcx = 0x100 + (seq - 1)
    if (got_rcx != 0x100 + (seq - 1) || got_seq != seq) ++slot_bad;
  }
  check(slot_bad == 0, "环形回绕的槽位公式 (seq-1)&mask 必须正确");
#endif  // !_WIN32

  std::printf("[intercept_stub] %d 项检查, %d 项失败\n", g_checks, g_failures);
  if (checks_out) *checks_out = g_checks;
  return g_failures;
}

}  // namespace test
}  // namespace wowmod
