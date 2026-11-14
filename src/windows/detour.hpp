// 目标进程内联 detour 引擎（Windows x64）。
//
// 与公开 Arctium 参照实现的区别（这几点决定了「为什么以前打不上/一打就崩」）：
//   1. 覆盖长度不写死。参照实现固定拷 13 字节、固定假设 EDX 是 FileDataID；
//      这里用 x64 长度解码器求出「完整指令边界」，只搬运整条指令。
//   2. 搬运的指令会重定位。RIP 相对寻址、call/jmp rel32 全部按新地址重算；
//      包含 rel8 跳转的 hook 点直接拒绝（无法安全重算）。
//   3. 每次远程内存操作都检查返回值，失败逐级回滚（不再「假装成功」）。
//   4. 页保护按 4 KB 对齐恢复，写完 FlushInstructionCache。
//   5. 可以在原指令边界上干净卸载（把原始字节写回）。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wowmod {
namespace win {

// 一段远程内存的持有者，析构时自动释放。
class RemoteBlock {
 public:
  RemoteBlock() = default;
  RemoteBlock(HANDLE process, size_t size, DWORD protect = PAGE_EXECUTE_READWRITE);
  ~RemoteBlock();
  RemoteBlock(const RemoteBlock&) = delete;
  RemoteBlock& operator=(const RemoteBlock&) = delete;
  RemoteBlock(RemoteBlock&& o) noexcept { swap(o); }
  RemoteBlock& operator=(RemoteBlock&& o) noexcept {
    if (this != &o) { release(); swap(o); }
    return *this;
  }

  uint8_t* addr() const { return addr_; }
  size_t size() const { return size_; }
  bool ok() const { return addr_ != nullptr; }
  void swap(RemoteBlock& o) noexcept {
    std::swap(process_, o.process_);
    std::swap(addr_, o.addr_);
    std::swap(size_, o.size_);
  }
  void release();

 private:
  HANDLE process_ = nullptr;
  uint8_t* addr_ = nullptr;
  size_t size_ = 0;
};

// 一个已经安装好的 detour。
struct Detour {
  uint64_t target = 0;         // 被 hook 的指令地址
  size_t copy_len = 0;         // 被搬走的原始字节数
  std::vector<uint8_t> original;// 原始字节（卸载时写回）
  RemoteBlock trampoline;      // 被搬走的指令 + 跳回原函数
  std::string name;
  bool installed = false;
  bool dry_run = false;   // 只验证未真正打补丁（演练模式）
};

// 安装 detour：
//   target          —— 目标进程内的指令地址（须落在完整指令边界上）
//   entry_stub      —— 目标进程内的代码地址（例如 shellcode），跳转到这里
//   trampoline_out  —— 输出：被搬走的原始指令所在地址（供 shellcode 跳回）
//   min_bytes       —— 需要覆盖的最小字节数（绝对 jmp = 14，rel32 = 5）
//
// 失败时目标进程内存不会被改动。成功返回 true。
// dry_run=true 时：分配跳板、搬运并重定位、校验指令边界，全都真实执行，
// 但【不写目标函数的补丁】。用来在零风险前提下验证"这个点到底能不能 hook"。
bool install_detour(HANDLE process, uint64_t target, uint64_t entry_stub, size_t min_bytes,
                    Detour* out, std::string* err, bool dry_run = false);

// 卸载：把原始字节写回并刷新指令缓存。
bool remove_detour(HANDLE process, Detour* d, std::string* err);

// 在目标进程里创建一段可执行代码并写入内容。
bool write_remote_code(HANDLE process, const std::vector<uint8_t>& code, RemoteBlock* out,
                       std::string* err);

// 读取目标进程内存（带错误文本）。
bool read_remote(HANDLE process, uint64_t addr, void* buf, size_t n, std::string* err);


// 改写目标进程内存（自动 VirtualProtectEx + 恢复 + FlushInstructionCache）。
bool write_remote(HANDLE process, uint64_t addr, const void* buf, size_t n, std::string* err,
                  bool flush_icache = true);

// 生成两种跳转桩：
//   build_abs_jump(dst)  -> 48 B8 <u64> FF E0             （14 字节，覆盖用）
//   build_rel32_jump(src,dst) -> E9 <rel32>              （5 字节，近距离时更省）
std::vector<uint8_t> build_abs_jump(uint64_t dst);
// rel32 距离超限时返回空。
std::vector<uint8_t> build_rel32_jump(uint64_t src, uint64_t dst);

// 把函数指针调用转成目标进程内的绝对地址（同位数进程直接可用）。
uint64_t self_addr(const void* p);

// 目标模块基址 / 大小。
bool module_range(HANDLE process, const std::wstring& module, uint64_t* base, size_t* size);

}  // namespace win
}  // namespace wowmod
#endif
