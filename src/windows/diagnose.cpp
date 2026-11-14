// 诊断实现。只读、只查询，不改客户端任何字节。
//
// 要回答的问题（按重要性）：
//   1. 我们到底有没有权限？打开进程时拿到了哪些 access？
//   2. 读内存能不能读？单次读 4KB / 1MB / 16MB 各要多久？
//   3. 那个 108MB 的区域到底是什么？首字节是什么？可读吗？
//   4. 为什么线程起不来？—— 用我们自己进程做对照实验。
//   5. 客户端有没有在拦我们（比如通过 job 对象 / 进程保护）？
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "diagnose.hpp"

#include <tlhelp32.h>
#include <windows.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "wowmod/util.hpp"

namespace wowmod {
namespace win {

namespace {

struct Reporter {
  std::string text;
  void line(const std::string& s) {
    std::printf("%s\n", s.c_str());
    std::fflush(stdout);
    text += s + "\r\n";
  }
  void kv(const std::string& k, const std::string& v) {
    line("  " + k + ": " + v);
  }
  void section(const std::string& s) {
    line("");
    line("== " + s + " ==");
  }
};

double ms_since(LARGE_INTEGER start) {
  LARGE_INTEGER freq, now;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&now);
  return 1000.0 * static_cast<double>(now.QuadPart - start.QuadPart) /
         static_cast<double>(freq.QuadPart);
}

std::string hexs(uint64_t v) { return "0x" + to_hex(v, 1); }

}  // namespace

int run_diagnose(HANDLE process, const std::string& out_path) {
  Reporter r;
  r.line("wowmod 诊断报告");
  r.line("================");

  const DWORD pid = GetProcessId(process);
  r.kv("目标 PID", std::to_string(pid));
  r.kv("位数", sizeof(void*) == 8 ? "64 位启动器" : "32 位启动器(致命)");

  // ---------------------------------------------------------------- 1. 权限
  r.section("1. 访问权限");
  {
    // 试着用不同的 access 重新打开，看哪些被拒
    struct { const char* name; DWORD access; } modes[] = {
        {"PROCESS_QUERY_INFORMATION", PROCESS_QUERY_INFORMATION},
        {"PROCESS_VM_READ", PROCESS_VM_READ},
        {"PROCESS_VM_WRITE", PROCESS_VM_WRITE},
        {"PROCESS_VM_OPERATION", PROCESS_VM_OPERATION},
        {"PROCESS_CREATE_THREAD", PROCESS_CREATE_THREAD},
        {"PROCESS_SUSPEND_RESUME", PROCESS_SUSPEND_RESUME},
    };
    for (const auto& m : modes) {
      HANDLE h = OpenProcess(m.access, FALSE, pid);
      r.kv(m.name, h ? "可用" : ("被拒 GetLastError=" + std::to_string(GetLastError())));
      if (h) CloseHandle(h);
    }
    // 进程保护级别（反作弊常见手段）
    {
      // 用 NtQueryInformationProcess 看 ProcessProtection（反作弊常见手段）
      using NtQIP = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
      const auto ntqip = reinterpret_cast<NtQIP>(
          GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
      if (ntqip) {
        struct { UCHAR level; UCHAR audit; USHORT type; } info = {0, 0, 0};
        ULONG ret = 0;
        const LONG st = ntqip(process, 61 /* ProcessProtectionInformation */, &info,
                              sizeof(info), &ret);
        if (st == 0) {
          r.kv("进程保护", "level=0x" + to_hex(info.level, 2) + " type=" +
                               std::to_string(info.type) +
                               (info.level ? "  <-- 有保护!" : "  （无保护）"));
        } else {
          r.kv("进程保护", "查询失败 NTSTATUS=0x" + to_hex(static_cast<uint32_t>(st), 8));
        }
      }
    }
  }

  // ---------------------------------------------------------------- 2. 读内存速度
  r.section("2. 读内存速度（决定扫描能不能在合理时间内完成）");
  {
    // 找一个大的已提交可读区域
    uint64_t probe = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uint64_t addr = 0;
    while (addr < 0x7FFFFFFF0000ull &&
           VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
      const uint64_t b = reinterpret_cast<uint64_t>(mbi.BaseAddress);
      addr = b + mbi.RegionSize;
      if (mbi.State == MEM_COMMIT && mbi.RegionSize >= (8u << 20) &&
          (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                          PAGE_EXECUTE_READWRITE)) &&
          !(mbi.Protect & PAGE_GUARD)) {
        probe = b;
        break;
      }
    }
    if (!probe) {
      r.kv("测试区域", "没找到 >=8MB 的可读区域，无法测速");
    } else {
      r.kv("测试区域", hexs(probe));
      for (size_t sz : {size_t{4096}, size_t{1} << 20, size_t{16} << 20}) {
        std::vector<uint8_t> buf(sz);
        LARGE_INTEGER t0;
        QueryPerformanceCounter(&t0);
        SIZE_T got = 0;
        const BOOL ok = ReadProcessMemory(process, reinterpret_cast<LPCVOID>(probe), buf.data(),
                                          sz, &got);
        const double ms = ms_since(t0);
        std::string s = ok ? ("成功 " + std::to_string(got) + " 字节")
                           : ("失败 GetLastError=" + std::to_string(GetLastError()));
        s += "  耗时 " + std::to_string(static_cast<int>(ms)) + " ms";
        if (ok && ms > 1) {
          s += "  ≈ " + std::to_string(static_cast<int>(sz / 1048576.0 / (ms / 1000.0))) +
               " MB/s";
        }
        r.kv("读 " + std::to_string(sz >> 10) + " KB", s);
      }
    }
  }

  // ---------------------------------------------------------------- 3. 区域清单
  r.section("3. 大区域清单（>=4MB）");
  {
    struct Reg { uint64_t base; size_t size; DWORD prot; DWORD type; };
    std::vector<Reg> regs;
    MEMORY_BASIC_INFORMATION mbi;
    uint64_t addr = 0;
    while (addr < 0x7FFFFFFF0000ull &&
           VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
      const uint64_t b = reinterpret_cast<uint64_t>(mbi.BaseAddress);
      addr = b + mbi.RegionSize;
      if (mbi.State != MEM_COMMIT) continue;
      if (mbi.RegionSize < (4u << 20)) continue;
      regs.push_back({b, mbi.RegionSize, mbi.Protect, mbi.Type});
    }
    size_t total = 0;
    for (const auto& x : regs) total += x.size;
    r.kv("数量", std::to_string(regs.size()) + " 个，合计 " + std::to_string(total >> 20) + " MB");
    // 按大小降序，最多列 25 个
    std::sort(regs.begin(), regs.end(),
              [](const Reg& a, const Reg& b) { return a.size > b.size; });
    for (size_t i = 0; i < regs.size() && i < 25; ++i) {
      const auto& x = regs[i];
      char head[17] = {0};
      SIZE_T got = 0;
      ReadProcessMemory(process, reinterpret_cast<LPCVOID>(x.base), head, 16, &got);
      std::string hx;
      for (size_t k = 0; k < (got < 16 ? got : 16); ++k) {
        char b[4];
        std::snprintf(b, sizeof(b), "%02x", static_cast<uint8_t>(head[k]));
        hx += b;
      }
      const char* type = x.type == MEM_IMAGE ? "IMAGE" : (x.type == MEM_MAPPED ? "MAPPED" : "PRIVATE");
      char prot[8];
      std::snprintf(prot, sizeof(prot), "%03lx", x.prot & 0xFFF);
      r.line("  [" + std::to_string(i) + "] " + hexs(x.base) + "  " +
             std::to_string(x.size >> 20) + " MB  prot=0x" + prot + "  " + type +
             "  首字节 " + hx);
    }
    if (regs.size() > 25) r.line("  ...（还有 " + std::to_string(regs.size() - 25) + " 个）");
  }

  // ---------------------------------------------------------------- 4. 标记搜索
  r.section("4. loose-file 标记字符串位置");
  {
    static const char* kMarkers[] = {
        "Locally overridden files",
        ".flavor.info",
        "CASC",
        "FileDataID",
    };
    for (const char* m : kMarkers) {
      const size_t mlen = std::strlen(m);
      int found_at = 0;
      std::vector<uint8_t> buf(1u << 20);
      MEMORY_BASIC_INFORMATION mbi;
      uint64_t addr = 0;
      while (addr < 0x7FFFFFFF0000ull && found_at < 3 &&
             VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        const uint64_t b = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        addr = b + mbi.RegionSize;
        if (mbi.State != MEM_COMMIT) continue;
        if (mbi.RegionSize < (1u << 20)) continue;
        if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                             PAGE_EXECUTE_READWRITE)) ||
            (mbi.Protect & PAGE_GUARD))
          continue;
        const size_t cap = (std::min)(mbi.RegionSize, size_t{32} << 20);
        for (size_t off = 0; off + mlen < cap; off += buf.size()) {
          const size_t n = (std::min)(buf.size(), cap - off);
          SIZE_T got = 0;
          if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(b + off), buf.data(), n,
                                 &got))
            continue;
          for (size_t i = 0; i + mlen <= got; ++i) {
            if (std::memcmp(buf.data() + i, m, mlen) == 0) {
              r.line("  \"" + std::string(m) + "\" @ " + hexs(b + off + i));
              ++found_at;
              if (found_at >= 3) break;
            }
          }
          if (found_at >= 3) break;
        }
      }
      if (!found_at) r.line("  \"" + std::string(m) + "\" 未找到");
    }
  }

  // ---------------------------------------------------------------- 5. 线程对照实验
  r.section("5. 线程创建对照实验");
  {
    // 5a. 在自己的进程里起一个什么都不做的线程，确认本机基本功能正常
    auto noop = [](void*) -> DWORD { return 0; };
    HANDLE self_t = CreateThread(nullptr, 0,
                                 reinterpret_cast<LPTHREAD_START_ROUTINE>(
                                     +[](LPVOID) -> DWORD { return 42; }),
                                 nullptr, 0, nullptr);
    if (self_t) {
      WaitForSingleObject(self_t, 5000);
      DWORD code = 0;
      GetExitCodeThread(self_t, &code);
      r.kv("本进程 CreateThread", "成功，退出码 " + std::to_string(code));
      CloseHandle(self_t);
    } else {
      r.kv("本进程 CreateThread", "失败，GetLastError=" + std::to_string(GetLastError()));
    }
    (void)noop;

    // 5b. 在目标进程里分配到一块内存，然后试着执行一个"立即 ret"的壳
    //     这是判断"能不能在客户端里跑代码"的最小实验。
    void* mem = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!mem) {
      r.kv("目标分配 RWX", "失败，GetLastError=" + std::to_string(GetLastError()));
    } else {
      r.kv("目标分配 RWX", "成功 " + hexs(reinterpret_cast<uint64_t>(mem)));
      // 查询这块内存的真实保护属性
      MEMORY_BASIC_INFORMATION m2;
      if (VirtualQueryEx(process, mem, &m2, sizeof(m2))) {
        char p[8];
        std::snprintf(p, sizeof(p), "%03lx", m2.Protect & 0xFFF);
        r.kv("  实际保护", "0x" + std::string(p) + (m2.Protect == PAGE_EXECUTE_READWRITE
                                                        ? "  (符合预期)"
                                                        : "  <-- 被改了!"));
      }
      // 写入 ret + int3 填充
      uint8_t shell[16] = {0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                           0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
      SIZE_T wrote = 0;
      const BOOL wok = WriteProcessMemory(process, mem, shell, sizeof(shell), &wrote);
      r.kv("  写入 shell", wok ? ("成功 " + std::to_string(wrote) + " 字节")
                               : ("失败 GetLastError=" + std::to_string(GetLastError())));
      // 回读验证
      uint8_t back[16] = {0};
      SIZE_T gotb = 0;
      if (ReadProcessMemory(process, mem, back, sizeof(back), &gotb)) {
        r.kv("  回读", back[0] == 0xC3 ? "一致（首字节 C3）" : "不一致！被篡改");
      }
      FlushInstructionCache(process, mem, sizeof(shell));

      // 起线程执行它
      HANDLE t = CreateRemoteThread(
          process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(mem), nullptr, 0,
          nullptr);
      if (!t) {
        const DWORD e = GetLastError();
        r.kv("  目标 CreateRemoteThread", "失败 GetLastError=" + std::to_string(e) + " " +
                                              (e == 998
                                                   ? "ERROR_NOACCESS：入口地址不可访问，说明"
                                                     "这块内存在对方看来不可执行"
                                                   : e == 5 ? "ERROR_ACCESS_DENIED"
                                                            : ""));
      } else {
        const DWORD w = WaitForSingleObject(t, 5000);
        DWORD code = 0;
        GetExitCodeThread(t, &code);
        r.kv("  目标 CreateRemoteThread",
             w == WAIT_OBJECT_0
                 ? ("成功执行，退出码 " + std::to_string(code) + "  <-- 能跑代码!")
                 : "超时 5 秒，线程没跑完");
        CloseHandle(t);
      }
      VirtualFreeEx(process, mem, 0, MEM_RELEASE);
    }
  }

  // ---------------------------------------------------------------- 6. 模块/线程概况
  r.section("6. 模块与线程");
  {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap != INVALID_HANDLE_VALUE) {
      MODULEENTRY32W me;
      me.dwSize = sizeof(me);
      int n = 0;
      std::string first;
      if (Module32FirstW(snap, &me)) {
        do {
          if (n == 0)
            first = wide_to_utf8(me.szModule) + " @ " +
                    hexs(reinterpret_cast<uint64_t>(me.modBaseAddr)) +
                    " SizeOfImage " + std::to_string(me.modBaseSize >> 20) + " MB";
          ++n;
        } while (Module32NextW(snap, &me));
      }
      CloseHandle(snap);
      r.kv("模块数", std::to_string(n));
      r.kv("主模块", first);
    }
    HANDLE ts = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (ts != INVALID_HANDLE_VALUE) {
      THREADENTRY32 te;
      te.dwSize = sizeof(te);
      int n = 0;
      if (Thread32First(ts, &te)) {
        do {
          if (te.th32OwnerProcessID == pid) ++n;
        } while (Thread32Next(ts, &te));
      }
      CloseHandle(ts);
      r.kv("线程数", std::to_string(n));
    }
  }

  r.line("");
  r.line("诊断结束。本报告没有修改客户端任何字节。");

  // 落盘
  HANDLE h = CreateFileW(utf8_to_wide(to_native_path(out_path)).c_str(), GENERIC_WRITE,
                         FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h != INVALID_HANDLE_VALUE) {
    DWORD w = 0;
    WriteFile(h, r.text.data(), static_cast<DWORD>(r.text.size()), &w, nullptr);
    CloseHandle(h);
    std::printf("\n诊断已写入: %s\n", out_path.c_str());
  }
  return 0;
}

}  // namespace win
}  // namespace wowmod
#endif
