// 目标进程内联 detour 实现。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/detour.hpp"

#include "wowmod/protect_plan.hpp"

#include <tlhelp32.h>

#include <algorithm>
#include <cstring>

#include "wowmod/util.hpp"
#include "wowmod/x64_decode.hpp"

namespace wowmod {
namespace win {

namespace {

std::string werr(const char* what) {
  return std::string(what) + " 失败, GetLastError=" + std::to_string(GetLastError());
}

size_t page_align_down(uint64_t a) { return static_cast<size_t>(a & ~uint64_t(0xFFF)); }

}  // namespace

RemoteBlock::RemoteBlock(HANDLE process, size_t size, DWORD protect) {
  if (!process || size == 0) return;
  process_ = process;
  addr_ = static_cast<uint8_t*>(
      VirtualAllocEx(process, nullptr, size, MEM_COMMIT | MEM_RESERVE, protect));
  if (addr_) size_ = size;
}

void RemoteBlock::release() {
  if (process_ && addr_) VirtualFreeEx(process_, addr_, 0, MEM_RELEASE);
  addr_ = nullptr;
  size_ = 0;
  process_ = nullptr;
}

RemoteBlock::~RemoteBlock() { release(); }

bool read_remote(HANDLE process, uint64_t addr, void* buf, size_t n, std::string* err) {
  SIZE_T got = 0;
  if (!ReadProcessMemory(process, reinterpret_cast<const void*>(addr), buf, n, &got) || got != n) {
    if (err) *err = werr("ReadProcessMemory");
    return false;
  }
  return true;
}

namespace {

}  // namespace

namespace {

// 按页改保护，逐页写入。
//
// 为什么必须逐页：VirtualProtectEx 要求的区间必须落在【同一批已提交页】里，
// 而且返回 ERROR_INVALID_PARAMETER(87) 最常见的原因就是
//   * 区间跨了页边界（各页归属不同分配/MEM_FREE 的页）
//   * 长度超过该区域实际可访问的范围
// 我们写的是客户端映像里的一条 14 字节跳转，只要 hook 点离页尾不到 14 字节
// 就会跨页 —— 那不是罕见情况，指令边界本来就随机。早期实现一次
// VirtualProtectEx 保护整段，跨页时直接 87 失败，表现为
// "拦截器安装失败: VirtualProtectEx(RWX) 失败, GetLastError=87"。
bool write_remote_paged(HANDLE process, uint64_t addr, const void* buf, size_t n,
                        std::string* err, bool flush_icache) {
  const uint8_t* src = static_cast<const uint8_t*>(buf);
  size_t done = 0;
  while (done < n) {
    const uint64_t cur = addr + done;
    const uint64_t page = cur & ~static_cast<uint64_t>(0xFFF);
    const size_t in_page = static_cast<size_t>(0x1000 - (cur - page));
    const size_t chunk = (n - done < in_page) ? (n - done) : in_page;

    // 先查这一页的真实状态：未提交/不可访问的页改保护必然 87。
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi)) == 0) {
      if (err) {
        char b[192];
        std::snprintf(b, sizeof(b),
                      "VirtualQueryEx(0x%llx) 失败, GetLastError=%lu",
                      static_cast<unsigned long long>(cur), GetLastError());
        *err = b;
      }
      return false;
    }
    if (mbi.State != MEM_COMMIT) {
      if (err) {
        char b[192];
        std::snprintf(b, sizeof(b), "目标 0x%llx 所在页未提交（State=%lu）",
                      static_cast<unsigned long long>(cur),
                      static_cast<unsigned long>(mbi.State));
        *err = b;
      }
      return false;
    }
    // 页内可写到哪为止
    const uint64_t page_end = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
    size_t max_here = chunk;
    if (cur + max_here > page_end) max_here = static_cast<size_t>(page_end - cur);
    if (max_here == 0) {
      if (err) *err = "目标页可用长度不足";
      return false;
    }

    // 改保护不能一律用 PAGE_EXECUTE_READWRITE。
    //
    // 客户端映像那块 108MB 是 MEM_MAPPED 的映像节（Type=MEM_IMAGE/MEM_MAPPED），
    // 对它请求 PAGE_EXECUTE_READWRITE 会 VirtualProtectEx 失败并返回
    // ERROR_INVALID_PARAMETER(87)：映像节的页保护必须与节原始属性兼容，
    // 不能"中途"把非执行节变成可执行页。
    //
    // 正确做法（业界通行）：对 MEM_MAPPED 用 PAGE_EXECUTE_WRITECOPY。
    // 语义上与 RWX 等价（可读可写可执行，写时复制，不会落盘），
    // 但它是映像节合法的保护值。私有内存(MEM_PRIVATE)才用 RWX。
    std::vector<DWORD> candidates;
    for (uint32_t v : wowmod::writable_protect_candidates(mbi.Type, mbi.Protect))
      candidates.push_back(static_cast<DWORD>(v));
    DWORD old = 0;
    DWORD used = 0;
    bool protected_ok = false;
    DWORD last_err = 0;
    for (DWORD want : candidates) {
      if (VirtualProtectEx(process, reinterpret_cast<void*>(cur), max_here, want, &old)) {
        protected_ok = true;
        used = want;
        break;
      }
      last_err = GetLastError();
    }
    if (!protected_ok) {
      if (err) {
        char b[320];
        std::snprintf(b, sizeof(b),
                      "VirtualProtectEx 失败于 0x%llx 长度 %zu（页首 0x%llx, 原保护 0x%lx, "
                      "State=0x%lx, Type=0x%lx, 试过 %zu 种保护）, GetLastError=%lu",
                      static_cast<unsigned long long>(cur), max_here,
                      static_cast<unsigned long long>(
                          reinterpret_cast<uint64_t>(mbi.BaseAddress)),
                      static_cast<unsigned long>(mbi.Protect),
                      static_cast<unsigned long>(mbi.State),
                      static_cast<unsigned long>(mbi.Type), candidates.size(), last_err);
        *err = b;
      }
      return false;
    }
    (void)used;
    SIZE_T wrote = 0;
    const bool ok =
        WriteProcessMemory(process, reinterpret_cast<void*>(cur), src + done, max_here, &wrote) &&
        wrote == max_here;
    DWORD ignored = 0;
    VirtualProtectEx(process, reinterpret_cast<void*>(cur), max_here, old, &ignored);
    if (!ok) {
      if (err) {
        char b[192];
        std::snprintf(b, sizeof(b), "WriteProcessMemory 失败于 0x%llx, GetLastError=%lu",
                      static_cast<unsigned long long>(cur), GetLastError());
        *err = b;
      }
      return false;
    }
    done += max_here;
  }
  if (flush_icache) FlushInstructionCache(process, reinterpret_cast<void*>(addr), n);
  return true;
}

}  // namespace

bool write_remote(HANDLE process, uint64_t addr, const void* buf, size_t n, std::string* err,
                  bool flush_icache) {
  return write_remote_paged(process, addr, buf, n, err, flush_icache);
}

std::vector<uint8_t> build_abs_jump(uint64_t dst) {
  std::vector<uint8_t> out = {0x48, 0xB8};
  out.resize(2 + 8);
  std::memcpy(out.data() + 2, &dst, 8);
  out.push_back(0xFF);
  out.push_back(0xE0);  // jmp rax
  return out;           // 14 字节
}

std::vector<uint8_t> build_rel32_jump(uint64_t src, uint64_t dst) {
  const int64_t delta = static_cast<int64_t>(dst) - static_cast<int64_t>(src + 5);
  if (delta > INT32_MAX || delta < INT32_MIN) return {};
  std::vector<uint8_t> out = {0xE9};
  const int32_t d = static_cast<int32_t>(delta);
  out.resize(5);
  std::memcpy(out.data() + 1, &d, 4);
  return out;
}

uint64_t self_addr(const void* p) { return reinterpret_cast<uint64_t>(p); }

bool module_range(HANDLE process, const std::wstring& module, uint64_t* base, size_t* size) {
  if (module.empty()) return false;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                         GetProcessId(process));
  if (snap == INVALID_HANDLE_VALUE) return false;
  MODULEENTRY32W me;
  me.dwSize = sizeof(me);
  bool found = false;
  if (Module32FirstW(snap, &me)) {
    do {
      std::wstring n = me.szModule;
      std::wstring want = module;
      for (auto& c : n) c = static_cast<wchar_t>(towlower(c));
      for (auto& c : want) c = static_cast<wchar_t>(towlower(c));
      if (n == want) {
        if (base) *base = reinterpret_cast<uint64_t>(me.modBaseAddr);
        if (size) *size = me.modBaseSize;
        found = true;
        break;
      }
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  return found;
}

bool write_remote_code(HANDLE process, const std::vector<uint8_t>& code, RemoteBlock* out,
                       std::string* err) {
  if (!out) return false;
  RemoteBlock blk(process, code.size(), PAGE_EXECUTE_READWRITE);
  if (!blk.ok()) {
    if (err) *err = werr("VirtualAllocEx(代码)");
    return false;
  }
  if (!write_remote(process, reinterpret_cast<uint64_t>(blk.addr()), code.data(), code.size(),
                    err)) {
    return false;
  }
  // 收紧为 RX：不留可写可执行页
  DWORD old = 0;
  VirtualProtectEx(process, blk.addr(), blk.size(), PAGE_EXECUTE_READ, &old);
  *out = std::move(blk);
  return true;
}

bool install_detour(HANDLE process, uint64_t target, uint64_t entry_stub, size_t min_bytes,
                    Detour* out, std::string* err, bool dry_run) {
  if (!process || !target || !entry_stub || !out) {
    if (err) *err = "参数无效";
    return false;
  }
  // 1. 读原始字节（多读一些，供解码与后续校验）
  std::vector<uint8_t> window(64, 0);
  if (!read_remote(process, target, window.data(), window.size(), err)) return false;

  // 2. 求完整指令边界
  const size_t copy_len = x64::find_safe_split(window.data(), window.size(), 0, min_bytes);
  if (copy_len == 0) {
    if (err) *err = "目标位置无法得到完整指令边界（hook 点必须落在指令开头）";
    return false;
  }

  // 3. 搬运并重定位
  std::vector<uint8_t> stolen(window.begin(), window.begin() + copy_len);
  // trampoline 地址先申请再重定位（重定位要知道目标地址）
  RemoteBlock code(process, copy_len + 32, PAGE_EXECUTE_READWRITE);
  if (!code.ok()) {
    if (err) *err = werr("VirtualAllocEx(trampoline)");
    return false;
  }
  const uint64_t tramp_va = reinterpret_cast<uint64_t>(code.addr());
  if (!x64::relocate_block(stolen, target, tramp_va)) {
    if (err) *err = "搬运区间内的相对位移无法重算（距离超出 rel32 或含 rel8 跳转）";
    return false;
  }
  // 接回原函数 target+copy_len
  {
    std::vector<uint8_t> back = build_abs_jump(target + copy_len);
    stolen.insert(stolen.end(), back.begin(), back.end());
  }
  if (!write_remote(process, tramp_va, stolen.data(), stolen.size(), err)) return false;
  DWORD old = 0;
  VirtualProtectEx(process, code.addr(), stolen.size(), PAGE_EXECUTE_READ, &old);

  // 4. 先备份原始字节，再打跳转
  out->target = target;
  out->copy_len = copy_len;
  out->original.assign(window.begin(), window.begin() + copy_len);

  std::vector<uint8_t> jump;
  const uint64_t stub_rel = entry_stub;
  if (copy_len >= 5) {
    // 优先试试 5 字节 rel32（省空间、对某些完整性检查更友好）
    jump = build_rel32_jump(target, stub_rel);
  }
  if (jump.empty()) jump = build_abs_jump(stub_rel);
  if (jump.size() > copy_len) {
    if (err) *err = "目标位置可用字节不足（需要 14 字节绝对跳转）";
    return false;
  }
  // 剩余字节用 int3 填充（不会被执行的区域）
  while (jump.size() < copy_len) jump.push_back(0xCC);

  // 5. 写入跳转并刷新指令缓存。
  //    演练模式(dry_run)到这里就停：跳板已经真实建好、重定位已校验，
  //    但目标函数一个字节都不改 —— 零风险地证明"这里能 hook"。
  if (dry_run) {
    out->trampoline = std::move(code);
    out->installed = false;   // 没有真正生效
    out->dry_run = true;
    return true;
  }
  if (!write_remote(process, target, jump.data(), jump.size(), err)) return false;

  out->trampoline = std::move(code);
  out->installed = true;
  return true;
}

bool remove_detour(HANDLE process, Detour* d, std::string* err) {
  if (!process || !d || !d->installed) return false;
  if (!write_remote(process, d->target, d->original.data(), d->original.size(), err)) return false;
  d->installed = false;
  d->trampoline.release();
  return true;
}

}  // namespace win
}  // namespace wowmod
#endif
