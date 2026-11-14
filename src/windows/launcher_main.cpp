// wowmod_loader.exe —— 真正可用的启动器。
//
// 它不再走「注入一个 DLL 然后祈祷模块表出现」那条路，而是把 wowmod_rt.dll
// 的代码【直接链接进自己】：
//
//   1. 创建游戏进程，挂起（CREATE_SUSPENDED）。
//   2. 在目标进程里手工映射自己的映像（按 PE 节分配 + 写入 + 处理重定位），
//      通过 InitOnce 执行入口点 —— 不需要 CreateRemoteThread / LoadLibraryW /
//      APC，也不是「DLL」，因此不受那几种被静默拒绝的路径影响。
//   3. 入口点先把目标进程【自己】的主模块摸一遍：等加载壳把它换成真实客户端
//      （或者等 Wow_loader.dll 解密完成），然后写分析报告。
//   4. 按 --mode 决定是否安装 hook，最后恢复主线程。
//
// 为什么这条路能成而之前不行：
//   * 之前的方案依赖「把某个 DLL 塞进模块表」——客户端加载层可以静默拒绝。
//   * 本方案改的是【已经在这个进程里的内存】。只要能把字节写进去、把线程跑起来，
//     就不需要对方同意"加载模块"。而挂起创建 + 手工映射 + 远程线程执行一个
//     已在内存里的函数，这三步都是纯内核操作。
//
// 需要：对目标进程 PROCESS_VM_WRITE / VM_OPERATION / CREATE_THREAD 权限
//      （同用户、同完整级别即可，不需要管理员）。
//
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include <windows.h>

// 构建标记：脚本自检会读这一行，确认 loader / ps1 是同一批产物。
// 每次改模式列表或脚本菜单时一起改，两边比对不上就直接告诉用户。
#ifndef WOWMOD_LOADER_BUILD_TAG
#define WOWMOD_LOADER_BUILD_TAG "sigscan-dump-v4"
#endif
#include <tlhelp32.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <cstring>
#include <string>
#include <conio.h>
#include <cstdlib>
#include <system_error>
#include <vector>

#include "wowmod/analyze.hpp"
#include "wowmod/launcher_stub.hpp"
#include "wowmod/util.hpp"
#include "wowmod/x64_decode.hpp"
#include "windows/fd_hook.hpp"
#include "windows/inject_first.hpp"
#include "windows/scan_images.hpp"
#include "windows/diagnose.hpp"
#include "windows/remote_analyze.hpp"
#include "windows/detour.hpp"
#include "windows/remote_load.hpp"
#include "windows/arctium_sig.hpp"
#include "windows/fs_scan.hpp"
#include "wowmod/json.hpp"



namespace wowmod {
std::string exe_dir_self();
}

namespace {

// 拦截器的环形缓冲/计数器地址（装在目标进程里，轮询时要用）
uint64_t g_ring_va = 0;
uint64_t g_counter_va = 0;

// ---- 从分析报告里读回 detour 目标，并在目标进程里真的装上拦截器 ----
//
// 为什么这么做：以前 auto 模式只打印一句"本版本先把结果给你"，拦截器根本
// 没装，所以用户永远拿不到 wowmod-intercept.log。拦截跳板是【纯记录】的
// （压栈保存全部寄存器 -> 写快照 -> 恢复 -> 跳回原函数），不改变客户端
// 任何行为，也不加载 DLL，因此不会触发 0x1100。

// 数一下 JSON 里某个数组有几个元素（用来比较哪次分析结果更好）
int count_json_array(const std::string& jtxt, const char* key) {
  std::string err;
  const wowmod::Json j = wowmod::Json::parse(jtxt, &err);
  if (j.is_null()) return 0;
  const wowmod::Json& a = j.at(key);
  return static_cast<int>(a.as_array().size());
}

uint64_t parse_base_from_json(const std::string& jtxt) {
  std::string err;
  const wowmod::Json j = wowmod::Json::parse(jtxt, &err);
  if (j.is_null()) return 0;
  const std::string b = j.at("baseVa").as_string();
  if (b.empty()) return 0;
  return std::strtoull(b.c_str(), nullptr, 16);
}

size_t install_interceptors_from_report(HANDLE process, const std::string& jtxt,
                                        uint64_t analysis_base, const std::string& log_path,
                                        std::vector<std::pair<uint64_t, std::string>>& out,
                                        bool dry_run) {
  std::string err;
  const wowmod::Json j = wowmod::Json::parse(jtxt, &err);
  if (j.is_null() || analysis_base == 0) return 0;

  std::vector<wowmod::win::InterceptTarget> targets;
  const wowmod::Json& dt = j.at("detourTargets");
  for (const wowmod::Json& t : dt.as_array()) {
    if (!t.at("hookable").as_bool()) continue;
    const std::string rva_hex = t.at("functionRva").as_string();
    if (rva_hex.empty()) continue;
    const uint64_t rva = std::strtoull(rva_hex.c_str(), nullptr, 16);
    wowmod::win::InterceptTarget it;
    it.target = analysis_base + rva;
    it.tag = t.at("marker").as_string();
    targets.push_back(it);
    out.push_back({it.target, it.tag});
    std::printf("  拦截目标 0x%s  rva=0x%s  [%s]\n",
                wowmod::to_hex(it.target, 16).c_str(), rva_hex.c_str(), it.tag.c_str());
    if (targets.size() >= 8) break;  // 最多 8 个，够用了
  }
  if (targets.empty()) return 0;

  // 计数器和环形缓冲都放在【目标进程】里
  wowmod::win::RemoteBlock counter(process, 8, PAGE_READWRITE);
  wowmod::win::RemoteBlock ring(process, 256 * wowmod::win::InterceptRecord::kSize, PAGE_READWRITE);
  if (!counter.ok() || !ring.ok()) {
    std::printf("  拦截器安装失败: 无法在客户端里分配记录缓冲\n");
    return 0;
  }
  const uint64_t zero = 0;
  wowmod::win::write_remote(process, reinterpret_cast<uint64_t>(counter.addr()), &zero, 8, nullptr, false);

  // 安装前先探测真实目标页：跨页 / 不可改保护都会在这里提前暴露，
  // 而不是等到最后丢一句 GetLastError=87 让人无从下手。
  for (const auto& t : targets) {
    const std::string pr = wowmod::win::probe_target_page(process, t.target, 14);
    std::printf("  页面探测: %s\n", pr.c_str());
  }

  // 再跑一次【演练】：跳板照常分配、指令照常搬运与重定位、边界照常校验，
  // 但目标函数一个字节都不写。这样能零风险地证明"这个点技术上能不能 hook"。
  // 仍然会改动客户端行为的只有真正的安装步骤。
  {
    std::vector<wowmod::win::Detour> dry;
    std::vector<wowmod::win::RemoteBlock> dry_stubs;
    std::string derr;
    if (wowmod::win::install_interceptors(process, targets, log_path,
                                          reinterpret_cast<uint64_t>(counter.addr()),
                                          reinterpret_cast<uint64_t>(ring.addr()), 256, &dry,
                                          &dry_stubs, &derr, /*dry_run=*/true)) {
      std::printf("  演练(不改目标): 通过 —— 指令边界/重定位/跳板都可用\n");
      for (const auto& d : dry)
        std::printf("    目标 0x%s 覆盖 %zu 字节（未写入）\n",
                    wowmod::to_hex(d.target, 16).c_str(), d.copy_len);
    } else {
      std::printf("  演练(不改目标): 失败 —— %s\n", derr.c_str());
    }
  }

  std::vector<wowmod::win::Detour> detours;
  std::vector<wowmod::win::RemoteBlock> stubs;
  if (!wowmod::win::install_interceptors(process, targets, log_path,
                                 reinterpret_cast<uint64_t>(counter.addr()),
                                 reinterpret_cast<uint64_t>(ring.addr()), 256, &detours, &stubs,
                                 &err, dry_run)) {
    std::printf("  拦截器安装失败: %s\n", err.c_str());
    return 0;
  }
  // 这些对象必须活到进程结束（卸载会把原始指令写回，等于撤掉拦截）
  static std::vector<wowmod::win::Detour> g_keep_detours;
  static std::vector<wowmod::win::RemoteBlock> g_keep_stubs;
  static wowmod::win::RemoteBlock g_keep_counter;
  static wowmod::win::RemoteBlock g_keep_ring;
  // 登记到全局槽位表：启动器意外退出时也要能把原始字节写回
  for (const auto& d : detours) {
    wowmod::win::register_installed_detour(&d);
  }
  g_keep_detours = std::move(detours);
  g_keep_stubs = std::move(stubs);
  g_keep_counter = std::move(counter);
  g_keep_ring = std::move(ring);
  g_ring_va = reinterpret_cast<uint64_t>(g_keep_ring.addr());
  g_counter_va = reinterpret_cast<uint64_t>(g_keep_counter.addr());
  return targets.size();
}

// 环形缓冲轮询：把每条记录（寄存器快照）追加到日志。
// 用户按回车结束。每条记录会尝试把 rcx/rdx/r8/r9 里像指针的值读出来看
// 是不是可打印字符串 —— 这就是判定 "FileDataID 在哪个参数" 的实证依据。
void poll_intercept_ring(HANDLE process, wowmod::win::RemoteAgent* agent, const std::string& log_path,
                         size_t target_count) {
  (void)agent;
  FILE* f = nullptr;
  {
    std::wstring w = wowmod::utf8_to_wide(wowmod::to_native_path(log_path));
    f = _wfopen(w.c_str(), L"ab");
  }
  if (!f) {
    std::printf("  无法打开记录文件: %s\n", log_path.c_str());
    return;
  }
  std::fprintf(f, "\n==== wowmod 拦截记录 (%zu 个目标) ====\n", target_count);
  std::fprintf(f, "每条 = 一次函数调用。字段：seq | rax rcx rdx r8 r9 | 可打印字符串\n\n");
  std::fflush(f);

  uint64_t last_seq = 0;
  size_t written = 0;
  const DWORD t0 = GetTickCount();
  bool running = true;
  int idle = 0;
  while (running) {
    const uint64_t counter = 0;
    uint64_t cur = 0;
    if (!wowmod::win::read_remote(process, g_counter_va, &cur, 8, nullptr)) break;
    (void)counter;
    if (cur > last_seq) {
      // 把新增的记录全部读出来
      const uint64_t ring_count = 256;
      const uint64_t from = last_seq + 1 > cur - ring_count ? last_seq + 1 : cur - ring_count + 1;
      // 槽位公式必须是 (seq - 1) & mask，不是 seq & mask：
      // 跳板用【自增前】的计数取槽（第一次调用写 slot 0），而记录里的 seq
      // 是自增后的值。写成 seq & mask 会整条错位一格，静默读到错误数据。
      for (uint64_t seq = from; seq <= cur; ++seq) {
        const uint64_t slot =
            ((seq - 1) & (ring_count - 1)) * wowmod::win::InterceptRecord::kSize;
        uint8_t rec[wowmod::win::InterceptRecord::kSize] = {0};
        if (!wowmod::win::read_remote(process, g_ring_va + slot, rec, sizeof(rec), nullptr)) continue;
        uint64_t rax = 0, rcx = 0, rdx = 0, r8 = 0, r9 = 0, rsp = 0, rseq = 0;
        std::memcpy(&rax, rec + wowmod::win::InterceptRecord::kRax, 8);
        std::memcpy(&rcx, rec + wowmod::win::InterceptRecord::kRcx, 8);
        std::memcpy(&rdx, rec + wowmod::win::InterceptRecord::kRdx, 8);
        std::memcpy(&r8, rec + wowmod::win::InterceptRecord::kR8, 8);
        std::memcpy(&r9, rec + wowmod::win::InterceptRecord::kR9, 8);
        std::memcpy(&rsp, rec + wowmod::win::InterceptRecord::kRsp, 8);
        std::memcpy(&rseq, rec + wowmod::win::InterceptRecord::kSeq, 8);
        if (rseq != seq) {  // 槽已被后续调用覆盖（环形回绕追上），跳过
          last_seq = seq;
          continue;
        }
        std::fprintf(f, "#%-6llu rax=%016llx rcx=%016llx rdx=%016llx r8=%016llx r9=%016llx\n",
                     static_cast<unsigned long long>(rseq),
                     static_cast<unsigned long long>(rax), static_cast<unsigned long long>(rcx),
                     static_cast<unsigned long long>(rdx), static_cast<unsigned long long>(r8),
                     static_cast<unsigned long long>(r9));
        // 试着把每个寄存器当指针读一段，看是不是可打印字符串
        const uint64_t regs[5] = {rcx, rdx, r8, r9, rax};
        const char* names[5] = {"rcx", "rdx", "r8", "r9", "rax"};
        for (int i = 0; i < 5; ++i) {
          if (regs[i] < 0x10000) continue;
          // 1) 寄存器本身当字符串指针
          char buf[128] = {0};
          if (wowmod::win::read_remote(process, regs[i], buf, sizeof(buf) - 1, nullptr)) {
            size_t len = 0;
            while (len < sizeof(buf) - 1 && buf[len] >= 0x20 && buf[len] < 0x7F) ++len;
            if (len >= 4) {
              std::fprintf(f, "          %s -> \"%s\"\n", names[i], std::string(buf, len).c_str());
              continue;
            }
          }
          // 2) 寄存器指向的槽里存着字符串指针
          uint64_t pointee = 0;
          if (wowmod::win::read_remote(process, regs[i], &pointee, 8, nullptr) && pointee > 0x10000) {
            char buf2[128] = {0};
            if (wowmod::win::read_remote(process, pointee, buf2, sizeof(buf2) - 1, nullptr)) {
              size_t len2 = 0;
              while (len2 < sizeof(buf2) - 1 && buf2[len2] >= 0x20 && buf2[len2] < 0x7F) ++len2;
              if (len2 >= 4)
                std::fprintf(f, "          %s -> *[%016llx] -> \"%s\"\n", names[i],
                             static_cast<unsigned long long>(pointee),
                             std::string(buf2, len2).c_str());
            }
          }
        }
        (void)rsp;
        last_seq = seq;
        ++written;
      }
      std::fflush(f);
      if (written % 16 == 0) std::printf("  已记录 %zu 次调用...\n", written);
      idle = 0;
    } else {
      ++idle;
    }
    // 最多记录 3 分钟，或者用户按回车停止
    if (GetTickCount() - t0 > 180000) {
      std::printf("\n  已达到 3 分钟上限，停止记录。\n");
      break;
    }
    if (idle % 20 == 0) {
      if (_kbhit()) {
        _getch();
        break;
      }
    }
    Sleep(100);
  }
  std::fprintf(f, "\n==== 结束，共记录 %zu 次调用 ====\n", written);
  std::fclose(f);
  std::printf("  共记录 %zu 次函数调用 -> %s\n", written, log_path.c_str());
}

}  // namespace

namespace {

using namespace wowmod;

struct Options {
  std::string exe;
  std::string workdir;
  std::string args;
  std::string mode = "observe";  // observe | auto | hook | analyze | pdata
  int wait_ms = 30000;
  bool keep_client = true;
  bool detach = true;      // 默认：确认运行时起来后就退出，不占着控制台
  bool verbose = false;
  // auto 模式默认只演练，不真的改客户端代码。
  // 为什么默认关：我们曾经把 hook 打到"崩溃日志格式化函数"上，
  // 一旦它被弄坏，游戏崩溃时崩溃处理器自己再挂 -> EXCEPTION_INTERNAL_ERROR。
  // 在确认目标语义之前，不要再让客户端冒这个风险。
  bool dry_run = true;
  bool dump_images = false;   // --dump：把可执行映像导出供离线分析
  bool dump_module = false;   // --dump-module：按 PE 节导出主模块完整映像
  bool dry_run_set = false;
};

void say(const std::string& s) {
  std::printf("%s\n", s.c_str());
  std::fflush(stdout);
}

std::string last_error() { return "GetLastError=" + std::to_string(GetLastError()); }

// ---- 远程内存小工具 ----
bool write_proc(HANDLE p, uint64_t addr, const void* src, size_t n, bool exec_ok = true) {
  DWORD old = 0;
  if (!VirtualProtectEx(p, reinterpret_cast<void*>(addr), n, PAGE_EXECUTE_READWRITE, &old))
    return false;
  SIZE_T w = 0;
  const bool ok = WriteProcessMemory(p, reinterpret_cast<void*>(addr), src, n, &w) && w == n;
  DWORD ign = 0;
  VirtualProtectEx(p, reinterpret_cast<void*>(addr), n, old, &ign);
  if (ok && exec_ok) FlushInstructionCache(p, reinterpret_cast<void*>(addr), n);
  return ok;
}

bool read_proc(HANDLE p, uint64_t addr, void* dst, size_t n) {
  SIZE_T got = 0;
  return ReadProcessMemory(p, reinterpret_cast<const void*>(addr), dst, n, &got) && got == n;
}

// ---- 手工映射一个 PE 到目标进程 ----
struct RemoteImage {
  uint64_t base = 0;
  size_t size = 0;
  uint64_t entry = 0;
};

bool map_image_remote(HANDLE p, const std::vector<uint8_t>& file, RemoteImage* out,
                      std::string* err) {
  const PeLayout pe = parse_pe_file(file);
  if (!pe.ok) {
    *err = "解析自身 PE 失败: " + pe.error;
    return false;
  }
  // 优先在自映像附近分配（重定位更简单）
  void* want = reinterpret_cast<void*>(static_cast<uintptr_t>(pe.image_base));
  void* mem = VirtualAllocEx(p, want, pe.size_of_image, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
  if (!mem) {
    mem = VirtualAllocEx(p, nullptr, pe.size_of_image, MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE);
  }
  if (!mem) {
    *err = "VirtualAllocEx 失败 " + last_error();
    return false;
  }
  const uint64_t base = reinterpret_cast<uint64_t>(mem);
  const int64_t delta = static_cast<int64_t>(base) - static_cast<int64_t>(pe.image_base);

  std::vector<uint8_t> img(pe.size_of_image, 0);
  const size_t hdr = pe.sections.empty() ? 0x400 : pe.sections[0].raw_ptr;
  std::memcpy(img.data(), file.data(), std::min(hdr, static_cast<size_t>(pe.size_of_image)));
  for (const auto& s : pe.sections) {
    if (s.raw_size == 0 || s.va >= pe.size_of_image) continue;
    const size_t n = std::min<size_t>({static_cast<size_t>(s.raw_size),
                                       file.size() > s.raw_ptr ? file.size() - s.raw_ptr : 0,
                                       pe.size_of_image - s.va});
    if (n) std::memcpy(img.data() + s.va, file.data() + s.raw_ptr, n);
  }
  // 处理基址重定位（只支持 DIR64）
  if (delta != 0) {
    for (const auto& r : pe.relocs) {
      if (r.type != 10) continue;  // IMAGE_REL_BASED_DIR64
      if (r.rva + 8 > img.size()) continue;
      uint64_t v = 0;
      std::memcpy(&v, img.data() + r.rva, 8);
      v += static_cast<uint64_t>(delta);
      std::memcpy(img.data() + r.rva, &v, 8);
    }
  }
  if (!write_proc(p, base, img.data(), img.size(), false)) {
    *err = "写入映像失败 " + last_error();
    return false;
  }
  out->base = base;
  out->size = pe.size_of_image;
  out->entry = base + pe.entry_rva;
  return true;
}

// ---- 找目标进程里真正的客户端主模块 ----
struct ModInfo {
  uint64_t base = 0;
  size_t size = 0;
  std::string name;
};

std::vector<ModInfo> modules_of(DWORD pid) {
  std::vector<ModInfo> out;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snap == INVALID_HANDLE_VALUE) return out;
  MODULEENTRY32W me;
  me.dwSize = sizeof(me);
  if (Module32FirstW(snap, &me)) {
    do {
      ModInfo m;
      m.base = reinterpret_cast<uint64_t>(me.modBaseAddr);
      m.size = me.modBaseSize;
      m.name = wide_to_utf8(me.szModule);
      out.push_back(std::move(m));
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  return out;
}

// ---- 等加载壳把真实客户端换进来 ----
// 判据（都不依赖版本号）：
//   1. exe 主模块的内存映像里出现 loose-file 相关字符串；
//   2. 或者出现 Wow_loader.dll/其他加载层模块，且其映像里出现真实代码特征。
bool image_ready(HANDLE p, const ModInfo& m, std::string* why) {
  if (m.size == 0) {
    if (why) *why = "模块大小为 0";
    return false;
  }
  // 分块读入模块内存，找标记字符串（不整块读，避免大模块耗时）
  std::vector<uint8_t> chunk(1 << 20);
  for (size_t off = 0; off < m.size; off += chunk.size()) {
    SIZE_T got = 0;
    const size_t n = std::min(chunk.size(), m.size - off);
    if (!ReadProcessMemory(p, reinterpret_cast<const void*>(m.base + off), chunk.data(), n, &got) ||
        got < 16)
      continue;
    for (const auto& marker : loose_file_markers()) {
      if (std::search(chunk.begin(), chunk.begin() + got, marker.text.begin(),
                      marker.text.end()) != chunk.begin() + got) {
        if (why) *why = "找到标记字符串: " + marker.text;
        return true;
      }
    }
  }
  if (why) *why = "未找到 loose-file 标记字符串（可能还在解密）";
  return false;
}

// ---- 在目标进程里执行一个函数（参数是 64 位整数） ----
bool remote_call(HANDLE p, uint64_t fn, uint64_t arg, DWORD* exit_code) {
  HANDLE t = CreateRemoteThread(p, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(fn),
                                reinterpret_cast<void*>(arg), 0, nullptr);
  if (!t) return false;
  const DWORD w = WaitForSingleObject(t, 120000);
  DWORD code = 0;
  GetExitCodeThread(t, &code);
  CloseHandle(t);
  if (exit_code) *exit_code = code;
  return w == WAIT_OBJECT_0;
}

}  // namespace

namespace {

// 路径参数如果没被引号包起来，命令行解析器会把它切成好几段：
//   --exe D:\Midnight Open Beta\_midnight_\WoW 12.0.7 - Firestorm.exe
// 会变成 --exe / D:\Midnight / Open / Beta\... / WoW / 12.0.7 / - / Firestorm.exe
// 这里把后续「不像选项、也不像已知取值」的片段一段段接回去，直到文件真的存在。
// 这样即便调用方漏了引号（PowerShell 5.1 的 Start-Process 坑），也不会失败。
std::string glue_path(int argc, char** argv, int* i) {
  if (*i + 1 >= argc) return std::string();
  std::string got = argv[++*i];
  if (!got.empty() && (got[0] == '-' || got[0] == '/')) return got;  // 明显是选项
  auto exists_now = [](const std::string& p) {
    std::error_code ec;
    return std::filesystem::exists(std::filesystem::u8path(p), ec) && !ec;
  };
  if (exists_now(got)) return got;
  // 往前拼：每次多接一段，中间补空格
  for (int guard = 0; guard < 24 && *i + 1 < argc; ++guard) {
    const std::string peek = argv[*i + 1];
    // 不要吞掉真正的选项
    if (peek.rfind("--", 0) == 0) break;
    got += " ";
    got += argv[++*i];
    if (exists_now(got)) return got;
  }
  return got;  // 拼不出来就原样返回，后面会给出清晰报错
}

}  // namespace

int main(int argc, char** argv) {
  Options o;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&](const char* def) -> std::string {
      if (i + 1 < argc) return argv[++i];
      return def;
    };
    if (a == "--dump") o.dump_images = true;
    else if (a == "--dump-module") o.dump_module = true;
    if (a == "--exe") o.exe = glue_path(argc, argv, &i);
    else if (a == "--workdir") o.workdir = glue_path(argc, argv, &i);
    else if (a == "--args") o.args = next("");
    else if (a == "--mode") o.mode = next("observe");
    else if (a == "--dry-run") o.dry_run = true;
    else if (a == "--apply") { o.dry_run = false; o.dry_run_set = true; }
    else if (a == "--wait") o.wait_ms = std::atoi(next("30000").c_str());
    else if (a == "--terminate-on-fail") o.keep_client = false;
    else if (a == "--wait-exit") o.detach = false;
    else if (a == "--no-detach") o.detach = false;
    else if (a == "--verbose") o.verbose = true;
    else if (a == "--version") {
      std::printf("wowmod_loader build: %s\n", WOWMOD_LOADER_BUILD_TAG);
      std::printf("modes: observe auto hook analyze diagnose sigscan\n");
      return 0;
    }
    else if (a == "-h" || a == "--help") {
      std::printf(
          "wowmod_loader.exe --exe \"...\\WoW 12.0.7 - Firestorm.exe\" [选项]\n\n"
          "  --mode observe   只分析并写报告（默认，不修改客户端任何字节）\n"
          "  --mode auto      分析后自动安装拦截记录（登录界面触发）\n"
          "  --mode hook      分析后直接安装 FileDataID 重定向（需要已确认 ABI）\n"
          "  --mode analyze   只分析，然后立刻退出（不等游戏窗口）\n"
          "  --mode diagnose  只做诊断，不改客户端任何字节（排查用）\n"
          "  --mode sigscan   用 Arctium 的公开特征码扫运行时映像，找真正的文件打开函数\n"
          "  --dump           sigscan 时把可执行映像导出到 wowmod\\dump（供 IDA 分析）\n"
          "  --dump-module    sigscan 时把【主模块】完整内存映像导出（含解密后的 .text）\n"
          "  --wait MS        等待客户端解密完成的最长时间（默认 30000）\n"
          "  --terminate-on-fail  失败时终止客户端（默认保留）\n"
          "  --wait-exit      一直等到客户端退出再返回（默认启动后即返回）\n\n"
          "报告位置: <游戏目录>\\wowmod\\wowmod-analysis.txt / .json\n"
          "          <游戏目录>\\wowmod\\wowmod_rt.log\n");
      return 0;
    }
  }
  if (o.exe.empty()) {
    std::printf("需要 --exe 指定客户端路径（--help 查看用法）\n");
    return 2;
  }
  o.exe = absolute_path(o.exe);
  {
    std::error_code ec;
    if (!std::filesystem::exists(std::filesystem::u8path(o.exe), ec) || ec) {
      std::printf("找不到客户端: %s\n", o.exe.c_str());
      std::printf("收到的原始参数:\n");
      for (int i = 0; i < argc; ++i) std::printf("  argv[%d] = %s\n", i, argv[i]);
      std::printf("提示: 路径含空格时整条路径必须用双引号包起来。\n");
      return 2;
    }
  }
  if (o.workdir.empty()) o.workdir = parent_path(o.exe);

  // 1) 检查位数
  std::vector<uint8_t> client_head;
  if (read_binary_file(o.exe, &client_head, nullptr)) {
    const PeLayout pe = parse_pe_file(client_head);
    if (pe.ok && pe.image_base == 0) {
      // 继续
    }
  }

  // 2) 挂起启动
  std::wstring cmd = L"\"" + wowmod::utf8_to_wide(to_native_path(o.exe)) + L"\"";
  if (!o.args.empty()) cmd += L" " + wowmod::utf8_to_wide(o.args);
  STARTUPINFOW si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));
  std::vector<wchar_t> buf(cmd.begin(), cmd.end());
  buf.push_back(L'\0');
  const std::wstring wd = wowmod::utf8_to_wide(to_native_path(o.workdir));
  if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr,
                      wd.c_str(), &si, &pi)) {
    std::printf("CreateProcess 失败: %s\n", last_error().c_str());
    return 3;
  }
  say("已创建客户端进程 PID " + std::to_string(pi.dwProcessId) + "（挂起）");

  // 模式白名单：必须在恢复客户端之前校验。
  // 以前这里没有校验，未知模式会静默掉进默认的分析路径 ——
  // 于是「特征码扫描」跑成了「字符串分析」，用户看到的是旧流程的输出，
  // 还以为新模式坏了。宁可当场报错，也不要跑一个不是用户要的模式。
  {
    const std::vector<std::string> known = {"observe", "auto", "hook", "analyze",
                                            "diagnose", "sigscan"};
    if (std::find(known.begin(), known.end(), o.mode) == known.end()) {
      std::printf("\n[错误] 未知模式 --mode %s\n", o.mode.c_str());
      std::printf("  支持的模式: ");
      for (size_t k = 0; k < known.size(); ++k)
        std::printf("%s%s", k ? " / " : "", known[k].c_str());
      std::printf("\n\n");
      std::printf("  这通常说明【启动器和脚本版本不匹配】：\n");
      std::printf("  脚本传了一个这个 exe 不认识的模式，于是旧 exe 会静默按默认分析跑，\n");
      std::printf("  让人以为新模式坏了。请确认 zip 里的 wowmod_loader.exe 与\n");
      std::printf("  scripts\\wowmod-start.ps1 是同一批产物。\n\n");
      std::printf("  本 exe 版本标记: %s\n", WOWMOD_LOADER_BUILD_TAG);
      TerminateProcess(pi.hProcess, 0);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 3;
    }
  }

  // 2b) 【必须】先恢复主线程。
  //
  // CREATE_SUSPENDED 只挂起了主线程，ntdll 的加载器初始化还没跑完。
  // 在挂起状态下调用 LoadLibraryW 一定失败（甚至 GetLastError 都拿不到，
  // 因为错误码是在加载器线程里设的）—— 这就是之前 "GetLastError=0" 的来源。
  // 正确顺序：先让加载器跑起来，再注入。
  ResumeThread(pi.hThread);
  say("已恢复客户端主线程（让 ntdll 加载器完成初始化）");
  ::Sleep(400);  // 给加载器一点时间建立模块表

  // 2c) 诊断模式：只报事实，不做任何修改。
  if (o.mode == "diagnose") {
    const std::string wowmod_dir = wowmod::join_path(o.workdir, "wowmod");
    CreateDirectoryW(utf8_to_wide(to_native_path(wowmod_dir)).c_str(), nullptr);
    wowmod::win::run_diagnose(pi.hProcess, wowmod::join_path(wowmod_dir, "wowmod-diagnose.txt"));
    std::printf("\n客户端保持运行。诊断文件: %s\\wowmod-diagnose.txt\n", wowmod_dir.c_str());
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
  }

  // 2d) 特征码模式：用 Arctium 的序言特征码找文件打开函数。只读，不改字节。
  if (o.mode == "sigscan") {
    const std::string wowmod_dir = wowmod::join_path(o.workdir, "wowmod");
    CreateDirectoryW(utf8_to_wide(to_native_path(wowmod_dir)).c_str(), nullptr);
    say("特征码扫描：按 Arctium 的序言特征码在运行时映像里找文件打开函数");
    // 等客户端把代码解密出来（12.0.7 是运行期解密）。报告事实，不要瞎等：
    // 每轮把「有没有标记 / 可执行映像数」打出来，用户能看到进展。
    bool ready = false;
    for (int i = 0; i < 40; ++i) {
      std::string marker;
      if (wowmod::win::process_has_client_markers(pi.hProcess, &marker)) {
        std::printf("  客户端代码已就绪（标记: %s）\n", marker.c_str());
        ready = true;
        break;
      }
      if (i % 5 == 0) std::printf("  等待客户端解密... (%d/40)\n", i);
      ::Sleep(500);
    }
    if (!ready)
      std::printf("  ！等满 20 秒仍未看到标记串，仍会继续扫描（结果会说明情况）\n");

    const auto res = wowmod::win::scan_arctium_signatures(pi.hProcess, o.exe);
    const std::string txt = wowmod::join_path(wowmod_dir, "wowmod-sigscan.txt");
    const std::string jso = wowmod::join_path(wowmod_dir, "wowmod-sigscan.json");
    Json rep = res.to_text_report();
    std::string werr;
    wowmod::write_text_file(txt, rep.at("text").as_string(), &werr);
    wowmod::write_text_file(jso, rep.at("json").dump(2), &werr);
    std::printf("\n%s\n", rep.at("text").as_string().c_str());
    std::printf("报告: %s\n", txt.c_str());

    // 在【解密后的内存】里定位文件打开函数。
    // 磁盘 exe 的 .text 是密文，这一步只能在运行期做；结果只有几行，
    // 不需要用户回传 100MB 的映像。
    say("在已解密的内存里定位文件打开函数（只读）");
    {
      const auto fs = wowmod::win::find_file_open_functions(pi.hProcess, 10);
      const std::string fsrep = wowmod::join_path(wowmod_dir, "wowmod-fsscan.txt");
      std::string ferr;
      wowmod::write_text_file(fsrep, fs.to_text_report().at("text").as_string(), &ferr);
      std::printf("\n%s\n", fs.to_text_report().at("text").as_string().c_str());
      std::printf("报告: %s\n", fsrep.c_str());
    }

    // 可选：把可执行映像落盘，供离线 IDA/x64dbg 分析。
    // 即使特征码全落空，这一次也能拿到后续分析需要的素材，不必反复重跑。
    if (o.dump_images) {
      const std::string ddir = wowmod::join_path(wowmod_dir, "dump");
      say("导出可执行映像（供离线分析）");
      const auto dumps = wowmod::win::dump_client_images(res.images, ddir);
      if (dumps.empty()) {
        std::printf("  没有找到可导出的可执行映像。\n");
      } else {
        for (const auto& d : dumps) {
          if (d.ok)
            std::printf("  0x%s  %.1f MB  标记命中 %zu -> %s\n",
                        wowmod::to_hex(d.base, 16).c_str(),
                        static_cast<double>(d.written) / (1024.0 * 1024.0), d.marker_hits,
                        d.path.c_str());
          else
            std::printf("  0x%s  失败: %s\n", wowmod::to_hex(d.base, 16).c_str(),
                        d.error.c_str());
        }
        std::printf("  说明: 写出的是运行时映像，RVA 可直接当文件偏移用。\n");
        bool any_client = false;
        for (const auto& d : dumps) if (d.ok && d.marker_hits > 0) any_client = true;
        if (!any_client)
          std::printf("  ！注意: 导出的文件【都不含】客户端标记串（CASC/FileDataID）。\n"
                      "    说明真正装客户端数据的映像这次没被选中，请把本输出发回。\n");
      }
    }
    // 导出主模块：磁盘上的 .text 是加密的（熵 8.00），只有内存里才是明文代码。
    //
    // 关键：壳是【按页惰性解密】的 —— 只有客户端真正跑到过的页才是明文。
    // 上一版在 ResumeThread 之后 400 ms 就抓，结果 113 MB 里只有 5.4 MB
    // （9.6%）是明文，剩下全是密文，等于白导。
    // 现在改成：反复采样"明文页占比"，直到它不再上升（或到达 --wait 上限）
    // 才真正导出。判据是实测数据，不是猜的时间。
    if (o.dump_module) {
      const std::string mdir = wowmod::join_path(wowmod_dir, "dump");
      CreateDirectoryW(utf8_to_wide(to_native_path(mdir)).c_str(), nullptr);
      const std::string mp = wowmod::join_path(mdir, "main-module.bin");

      size_t best_low = 0;
      int stable = 0;
      const DWORD t_start = GetTickCount();
      say("采样 .text 解密进度（等比例稳定后再导出）");
      for (;;) {
        const auto probe = wowmod::win::dump_module_full(pi.hProcess, "", "");
        if (!probe.text_checked) {
          std::printf("  采样失败（模块尚未就绪），继续等...\n");
        } else {
          const double ratio = static_cast<double>(probe.text_low_entropy) /
                               static_cast<double>(probe.text_checked);
          std::printf("  %4.0f ms: 明文页 %zu/%zu = %.1f%%\n",
                      static_cast<double>(GetTickCount() - t_start),
                      probe.text_low_entropy, probe.text_checked, ratio * 100.0);
          std::fflush(stdout);
          // 用「明文页数」判断进步，而不是比例：一次多解出 1 页（1/256≈0.39%）
          // 也是真进步，用比例加容差会把这种微小增长误判成"已稳定"。
          if (probe.text_low_entropy > best_low) {
            best_low = probe.text_low_entropy;
            stable = 0;
          } else {
            stable++;
          }
        }
        if (stable >= 3) {
          std::printf("  比例已稳定（连续 3 次没上升），开始导出。\n");
          break;
        }
        if (GetTickCount() - t_start >= static_cast<DWORD>(o.wait_ms)) {
          std::printf("  到达 --wait 上限 %d ms，按当前状态导出。\n", o.wait_ms);
          break;
        }
        ::Sleep(1000);
      }

      say("导出主模块完整映像（含解密后的 .text）");
      const auto md = wowmod::win::dump_module_full(pi.hProcess, "", mp);
      if (!md.ok) {
        std::printf("  失败: %s\n", md.error.c_str());
      } else {
        std::printf("  基址 0x%s  SizeOfImage %.1f MB  实际读到 %.1f MB\n",
                    wowmod::to_hex(md.base, 16).c_str(),
                    static_cast<double>(md.size_of_image) / (1024.0 * 1024.0),
                    static_cast<double>(md.written) / (1024.0 * 1024.0));
        if (md.text_checked)
          std::printf("  明文页: %zu/%zu = %.1f%%\n", md.text_low_entropy,
                      md.text_checked,
                      100.0 * static_cast<double>(md.text_low_entropy) /
                          static_cast<double>(md.text_checked));
        std::printf("  节表:\n");
        for (const auto& sec : md.sections) std::printf("    %s\n", sec.c_str());
        std::printf("  文件: %s\n", md.path.c_str());
        std::printf("  说明: RVA 可直接当文件偏移用。\n");
        // 比例很低说明客户端还没跑到那些代码 —— 只有真正进游戏、换装、
        // 打开角色面板，才会把模型/文件名解析相关的页解密出来。
        if (md.text_checked && md.text_low_entropy * 5 < md.text_checked)
          std::printf("  ！明文只有 %.1f%%，偏少。\n"
                      "    请先登进游戏、切一次角色/换一套模型，再重跑本命令导出。\n",
                      100.0 * static_cast<double>(md.text_low_entropy) /
                          static_cast<double>(md.text_checked));
      }
    }

    std::printf("\n客户端保持运行，本次扫描没有修改任何字节。\n");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
  }

  // 3) 零模块方案：不加载任何 DLL，直接在目标进程里跑自己的机器码。
  //
  //    这是【唯一】不会触发客户端 0x1100「检测到不受支持的软件」的路径：
  //    客户端扫描的是模块表，而我们写的这块内存没有 PE 头、不在模块表里。
  if (o.mode != "dll") {
    wowmod::win::RemoteAgent agent;
    std::string err;
    // 代理是【可选的加速手段】，不是必需品：
    // 分析和 hook 安装都只需要远程读写内存（ReadProcessMemory /
    // WriteProcessMemory / VirtualProtectEx），完全不需要在客户端里执行代码。
    // 所以代理起不来不影响功能，只是无法在客户端内部调用函数而已。
    bool agent_ok = false;
    if (agent.attach(pi.hProcess, &err)) {
      uint64_t r0 = 0;
      if (agent.command(wowmod::win::kAgentPing, 0x1234, 0, &r0, nullptr, &err)) {
        agent_ok = true;
        std::printf("  [成功] 远程代理已驻留（无模块，不会触发 0x1100）\n");
        std::printf("  [成功] 代理通讯正常（回声 0x%s）\n", wowmod::to_hex(r0, 16).c_str());
      }
    }
    if (!agent_ok) {
      std::printf("  [跳过] 远程代理不可用: %s\n", err.c_str());
      std::printf("         这不影响分析 —— 分析改成纯远程读写内存实现。\n");
      agent.detach();
    }

    // ---- 真正干活：远程分析 + 按模式安装 hook ----
    const std::string wowmod_dir = wowmod::join_path(o.workdir, "wowmod");
    std::string alog;
    std::string best_json;   // 多轮尝试里最好的一份分析结果

    // 先探测写权限：这决定了后面能不能真的装 hook，还是只能出报告。
    {
      const auto wp = wowmod::win::probe_write_capability(pi.hProcess);
      std::printf("  写入能力: 分配RW=%s 分配RWX=%s 写入=%s 改保护=%s  [%s]\n",
                  wp.alloc_rw ? "是" : "否", wp.alloc_rx ? "是" : "否",
                  wp.write_ok ? "是" : "否", wp.protect_ok ? "是" : "否", wp.detail.c_str());
      alog += "写入能力: RW=" + std::string(wp.alloc_rw ? "1" : "0") +
              " RWX=" + std::string(wp.alloc_rx ? "1" : "0") +
              " write=" + std::string(wp.write_ok ? "1" : "0") +
              " protect=" + std::string(wp.protect_ok ? "1" : "0") +
              " (" + wp.detail + ")\n";
      if (!wp.alloc_rx) {
        std::printf("  注意：无法在客户端里分配可执行内存 —— hook 跳板放不进去。\n"
                    "        分析仍然可用，但'安装替换'这条路会被堵住。\n");
      }
    }

    // 不再"先轮询等解密、再分析" —— 那等于把整个进程读两遍，看起来就像卡死。
    // 改成：直接分析一次，没命中就隔一会儿重试，每次重试都会打印进度。
    std::printf("开始分析客户端内存（读不到就自动重试，最长 %d ms）...\n", o.wait_ms);
    // 客户端会反复重新映射主映像（日志里能看到同一块区域每次地址都不同），
    // 而且不同副本里"被 lea 引用的字符串"数量不一样：有的只有数据、
    // 有的代码段完整。所以多试几次，取【结果最好的一次】——
    // 绝不能让后面更差的尝试覆盖掉前面已经拿到的 detour 目标。
    const DWORD t0 = GetTickCount();
    int rc = -1;
    int attempt = 0;
    int best_detour = -1;
    int best_strings = -1;
    const std::string report_json = wowmod::join_path(wowmod_dir, "wowmod-analysis.json");
    while (GetTickCount() - t0 < static_cast<DWORD>(o.wait_ms)) {
      ++attempt;
      alog.clear();
      std::printf("\n--- 第 %d 次尝试 ---\n", attempt);
      const int this_rc = wowmod::win::analyze_remote_and_write(pi.hProcess, wowmod_dir, &alog);
      std::printf("%s", alog.c_str());
      std::fflush(stdout);
      if (this_rc == 0) rc = 0;

      std::string jt;
      std::string je;
      wowmod::read_text_file(report_json, &jt, &je);
      const int d = count_json_array(jt, "detourTargets");
      const int sh = count_json_array(jt, "stringHits");
      std::printf("  本次结果: 字符串 %d 个, detour %d 个\n", sh, d);
      if (d > best_detour || (d == best_detour && sh > best_strings)) {
        best_detour = d;
        best_strings = sh;
        best_json = jt;
        if (d > 0) std::printf("  [保留] 目前最好（字符串 %d, detour %d）\n", sh, d);
      }
      if (best_detour > 0) break;   // 已经拿到可用目标，不用再试
      if (attempt >= 6) break;
      ::Sleep(1500);
    }
    // 把最好的那份结果写回报告，后面安装拦截器读的就是它
    if (best_detour > 0 && !best_json.empty()) {
      std::string we;
      wowmod::write_text_file(report_json, best_json, &we);
      std::printf("\n[汇总] 共尝试 %d 次，采用最好的一次：字符串 %d 个, detour %d 个\n",
                  attempt, best_strings, best_detour);
    }

    if (rc != 0) {
      std::printf("\n分析未成功（code=%d）。诊断已写入 %s\\wowmod-analysis.txt\n", rc,
                  wowmod_dir.c_str());
    } else {
      std::printf("\n分析报告: %s\\wowmod-analysis.txt\n", wowmod_dir.c_str());
    }

    // 装上 hook（observe 模式不装）
    if (rc == 0 && o.mode != "observe") {
      if (o.mode == "hook") {
        std::printf("\n[mode=hook] 重定向安装需要已知 FileDataID 参数位置。\n"
                    "  请先用 auto 模式拿到 wowmod-intercept.log，再回来用 hook。\n");
      } else if (o.mode == "auto") {
        std::printf("\n[mode=auto] 模式: %s\n",
                    o.dry_run ? "演练（不改客户端任何字节）" : "真正安装（会改客户端代码）");
        // 从刚写出的报告里读回「推荐 detour 目标」，然后【真的】装拦截器。
        // 拦截跳板只记录寄存器快照，不改变客户端任何行为，也不加载 DLL。
        const std::string report = wowmod::join_path(wowmod_dir, "wowmod-analysis.json");
        std::string jerr;
        std::string jtxt;
        read_text_file(report, &jtxt, &jerr);
        std::vector<std::pair<uint64_t, std::string>> targets;  // VA + 标记
        uint64_t analysis_base = 0;
        if (!jtxt.empty()) analysis_base = parse_base_from_json(jtxt);
        const std::string intercept_log = wowmod::join_path(wowmod_dir, "wowmod-intercept.log");
        const size_t n = install_interceptors_from_report(pi.hProcess, jtxt, analysis_base,
                                                          intercept_log, targets, o.dry_run);
        if (n == 0) {
          // 区分两种情况，别把"安装失败"说成"没有目标"——后者会让人
          // 以为是分析的问题，而实际分析已经成功了。
          if (!targets.empty()) {
            std::printf("\n[mode=auto] 分析成功（找到 %zu 个 detour 目标），但【安装失败】。\n",
                        targets.size());
            for (const auto& t : targets)
              std::printf("  目标 0x%s [%s]\n", wowmod::to_hex(t.first, 16).c_str(),
                          t.second.c_str());
            std::printf("  失败原因见上面那行「拦截器安装失败: ...」。\n");
          } else {
            std::printf("\n[mode=auto] 分析没找到任何 detour 目标。\n"
                        "  报告已生成，看 wowmod-analysis.txt 的「1) 字符串与交叉引用」。\n");
          }
        } else {
          if (o.dry_run) {
            std::printf("\n[mode=auto] 演练通过：%zu 个目标【技术上可 hook】。\n", n);
            std::printf("  ！本次【没有】改动客户端任何字节（--dry-run 默认开启）。\n");
            std::printf("  日志: %s\n", intercept_log.c_str());
            std::printf("  要真正安装请用 --apply（会有崩溃风险，先看报告确认目标语义）。\n");
          } else {
            std::printf("\n[mode=auto] 已安装 %zu 个拦截器（只记录，不改变客户端行为）。\n", n);
            std::printf("  记录文件: %s\n", intercept_log.c_str());
            std::printf("  现在去登录界面 → 进角色选择 → 进游戏，然后按回车停止记录。\n");
            std::fflush(stdout);
            // 轮询环形缓冲，把每次调用的寄存器快照追加到日志
            poll_intercept_ring(pi.hProcess, &agent, intercept_log, targets.size());
          }
        }
      }
    }

    agent.detach();

    // auto 模式不能 detach：轮询环形缓冲、写 intercept log 全靠这个循环，
    // 一 detach 就立刻退出，"拦截器已装好"变成一句空话（用户拿不到日志）。
    const bool must_stay = (o.mode == "auto");
    if (o.detach && !must_stay) {
      const DWORD alive = WaitForSingleObject(pi.hProcess, 2500);
      if (alive == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        std::printf("\n客户端在分析后立刻退出（退出码 %lu）。\n", code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 7;
      }
      say("客户端正在运行。报告见 " + wowmod_dir + "\\wowmod-analysis.txt");
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 0;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
  }

  // 3) 把 wowmod_rt.dll 送进目标进程。依次尝试三条路径，全部失败才报错。
  {
    const std::string dll = wowmod::join_path(exe_dir_self(), "wowmod_rt.dll");
    if (!file_exists(dll)) {
      std::printf("缺少 %s（应与本程序在同一目录）\n", dll.c_str());
      if (!o.keep_client) TerminateProcess(pi.hProcess, 1);
      return 4;
    }
    std::vector<wowmod::win::LoadAttempt> attempts;
    const auto best = wowmod::win::load_runtime(pi.hProcess, dll, &attempts);
    for (const auto& at : attempts) {
      std::printf("  [%s] %s\n", at.ok ? "成功" : "失败", at.method.c_str());
      if (!at.detail.empty()) std::printf("         %s\n", at.detail.c_str());
    }
    if (!best.ok) {
      // 把每次尝试的结果也落盘，方便复制
      {
        std::string txt;
        for (const auto& at : attempts) {
          txt += std::string(at.ok ? "[OK] " : "[FAIL] ") + at.method + "\n";
          if (!at.detail.empty()) txt += "    " + at.detail + "\n";
        }
        std::vector<uint8_t> b(txt.begin(), txt.end());
        const std::string out = wowmod::join_path(o.workdir, "wowmod\\load-attempts.txt");
        CreateDirectoryW(utf8_to_wide(to_native_path(join_path(o.workdir, "wowmod"))).c_str(),
                         nullptr);
        HANDLE h = CreateFileW(utf8_to_wide(to_native_path(out)).c_str(), GENERIC_WRITE,
                               FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                               nullptr);
        if (h != INVALID_HANDLE_VALUE) {
          DWORD w = 0;
          WriteFile(h, b.data(), static_cast<DWORD>(b.size()), &w, nullptr);
          CloseHandle(h);
          std::printf("\n详细结果已写入: %s\n", out.c_str());
        }
      }
      std::printf(
          "\n三条加载路径全部失败。这不是版本问题，是加载被拒绝。\n"
          "如果上面出现 126（找不到模块），说明 wowmod_rt.dll 依赖的\n"
          "VC++ 运行库不在客户端目录里 —— 换成本次构建的 static 版本即可。\n");
      if (!o.keep_client) TerminateProcess(pi.hProcess, 1);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 6;
    }
    std::printf("运行时已就位（%s），模块基址 0x%s\n", best.method.c_str(),
                wowmod::to_hex(best.module_base, 16).c_str());
    if (best.method.find("手工映射") != std::string::npos) {
      // 手工映射不会触发系统加载器，因此 **CRT 根本没有初始化**：
      // std::string / operator new / 静态构造全是未定义行为。
      // 正确做法是按 DllMain 语义调用 PE 入口点
      //   _DllMainCRTStartup(hinst, DLL_PROCESS_ATTACH, 0)
      // 它会先跑 CRT 初始化，再调用我们的 DllMain。
      const std::string dll2 = wowmod::join_path(exe_dir_self(), "wowmod_rt.dll");
      std::vector<uint8_t> f;
      uint32_t entry_rva = 0;
      if (read_binary_file(dll2, &f, nullptr)) {
        const PeLayout pe = parse_pe_file(f);
        if (pe.ok) entry_rva = pe.entry_rva;
      }
      if (!entry_rva) {
        std::printf("  警告：读不到 DLL 入口点，运行时未启动\n");
      } else {
        std::string err;
        // arg1 = DLL_PROCESS_ATTACH(1)，arg2 = 0
        const auto r = wowmod::win::call_remote(pi.hProcess, best.module_base + entry_rva,
                                        best.module_base, 1, 0, 60000, &err);
        if (!r.ran) {
          std::printf("  调用 DllMain 失败: %s\n", err.c_str());
        } else if (r.r0 == 0) {
          std::printf("  入口点返回 FALSE —— 初始化失败（若已生成 wowmod_rt.log 请看它）\n");
        } else {
          std::printf("  运行时已启动（入口点返回 TRUE）\n");
        }
      }
    }
  }

  // 4) 客户端已经在运行（步骤 2b 已恢复）
  say("客户端正在运行");

  if (o.mode == "analyze") {
    WaitForSingleObject(pi.hProcess, 3000);
    // 报告由进程内线程写出，这里直接退出（客户端继续跑）
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    say("分析模式：客户端继续运行，请查看 wowmod\\wowmod-analysis.txt");
    return 0;
  }

  if (o.detach) {
    // 确认客户端没有立刻崩掉，然后把控制台还给用户。
    // 运行时线程在客户端进程内继续工作（写报告、等登录界面、按热键）。
    const DWORD alive = WaitForSingleObject(pi.hProcess, 2500);
    if (alive == WAIT_OBJECT_0) {
      DWORD code = 0;
      GetExitCodeProcess(pi.hProcess, &code);
      std::printf("客户端在启动后 2.5 秒内退出（退出码 %lu）。\n"
                  "如果这不是你手动关的，说明载入运行时导致客户端崩溃：\n"
                  "请把 %s\\wowmod\\wowmod_rt.log 发出来。\n",
                  code, o.workdir.c_str());
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 7;
    }
    say("客户端正在运行，运行时已驻留其中。本窗口可以关闭。");
    say("报告（进到登录界面后生成）: " + wowmod::join_path(o.workdir, "wowmod\\wowmod-analysis.txt"));
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
  }

  WaitForSingleObject(pi.hProcess, INFINITE);
  wowmod::win::emergency_remove_all(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  say("客户端已退出");
  return 0;
}

// exe 自身路径（供读取本映像）
namespace wowmod {
std::string exe_dir_self() {
  wchar_t buf[MAX_PATH * 4] = {0};
  const DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
  return n ? parent_path(wide_to_utf8(std::wstring(buf, n))) : std::string();
}
}  // namespace wowmod

#endif  // _WIN32
