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
#define WOWMOD_LOADER_BUILD_TAG "patch-v15"
#endif
#include <tlhelp32.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <map>
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
#include "windows/arctium_patch.hpp"
#include "windows/mod_loader.hpp"
#include "wowmod/mods_selfcontained.hpp"
#include "windows/probe_reader.hpp"
#include "windows/crash_evidence.hpp"
#include "windows/fd_hook.hpp"
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
  bool stub_native = false;   // --stub native 时用本项目生成器
  // auto 模式默认只演练，不真的改客户端代码。
  // 为什么默认关：我们曾经把 hook 打到"崩溃日志格式化函数"上，
  // 一旦它被弄坏，游戏崩溃时崩溃处理器自己再挂 -> EXCEPTION_INTERNAL_ERROR。
  // 在确认目标语义之前，不要再让客户端冒这个风险。
  bool dry_run = true;
  bool dump_images = false;   // --dump：把可执行映像导出供离线分析
  bool dump_module = false;   // --dump-module：按 PE 节导出主模块完整映像
  bool dry_run_set = false;
  // probe 用哪个特征码定位目标。默认 CustomFileIdHook（老目标），
  // 但实测它只加载 interface/sound，所以允许切换到 FileIdLookupFNV。
  std::string probe_sig = "CustomFileIdHook";
  // patch 模式的兜底：当同一段代码被映射多份、无法自动判定该改哪一份时，
  // 允许用 --rva NAME=0x... 点名。值是【相对主模块的 RVA】，来自离线 dump 的实测。
  std::vector<std::pair<std::string, uint32_t>> patch_rva;

  // ---- 自包含模式（不需要 python / 不需要预先生成 mappings）----
  // Arctium 的形态是 exe + mappings\ + files\；
  // 这里允许直接把「模组目录 + listfile」交给 exe，由 exe 自己换算。
  std::string mods_dir;
  std::string listfile_spec;   // 多个文件用 ';' 分隔
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
    else if (a == "--target") o.probe_sig = next("CustomFileIdHook");
    else if (a == "--rva") {
      // 形式：--rva LoadByFileIdAlternate=0x33d7976
      const std::string v = next("");
      const size_t eq = v.find('=');
      if (eq != std::string::npos) {
        const std::string nm = v.substr(0, eq);
        const uint32_t rv = static_cast<uint32_t>(
            std::strtoull(v.c_str() + eq + 1, nullptr, 0));
        o.patch_rva.push_back({nm, rv});
      }
    }
    else if (a == "--terminate-on-fail") o.keep_client = false;
    else if (a == "--wait-exit") o.detach = false;
    else if (a == "--no-detach") o.detach = false;
    else if (a == "--mods") o.mods_dir = glue_path(argc, argv, &i);
    else if (a == "--listfile") o.listfile_spec = glue_path(argc, argv, &i);
    else if (a == "--verbose") o.verbose = true;
    else if (a == "--stub") {
      const std::string v = next("arctium");
      o.stub_native = (v == "native");
    }
    else if (a == "--version") {
      std::printf("wowmod_loader build: %s\n", WOWMOD_LOADER_BUILD_TAG);
      std::printf("modes: observe auto hook analyze diagnose sigscan probe scout patch mods\n");
      return 0;
    }
    else if (a == "-h" || a == "--help") {
      std::printf(
          "wowmod_loader.exe --exe \"...\\WoW 12.0.7 - Firestorm.exe\" [选项]\n\n"
          "  --mode observe   只分析并写报告（默认，不修改客户端任何字节）\n"
          "  --mode auto      分析后自动安装拦截记录（客户端窗口出现后触发）\n"
          "  --mode hook      分析后直接安装 FileDataID 重定向（需要已确认 ABI）\n"
          "  --mode analyze   只分析，然后立刻退出（不等游戏窗口）\n"
          "  --mode diagnose  只做诊断，不改客户端任何字节（排查用）\n"
          "  --mode sigscan   用 Arctium 的公开特征码扫运行时映像，找真正的文件打开函数\n"
          "  --mode probe     【旁路记录】在 FileDataID 查找函数上装跳板，只记录客户端实际\n"
          "                   传入了哪些 id，不改变任何返回值（无风险，用来确认 ABI）\n"
          "  --mode mods      【完整机制】anti-crash + NoJump + FileDataID 查表跳板，三件一起上\n"
          "  --mode patch     【Arctium 机制】把「按 FileDataID/路径从 CASC 加载」的\n"
          "                   条件跳转改成不跳（4 个 00），让客户端回头查本地文件。\n"
          "                   这是 Arctium 真正用的做法，不加 hook、不搬指令、不写跳板\n"
          "  --dump           sigscan 时把可执行映像导出到 wowmod\\dump（供 IDA 分析）\n"
          "  --dump-module    sigscan 时把【主模块】完整内存映像导出（含解密后的 .text）\n"
          "  --rva NAME=0xRVA patch 模式兜底：点名要改哪一份副本（相对主模块的 RVA）。\n"
          "                   只在自动判定拒绝安装时才需要，例如\n"
          "                   --rva LoadByFileIdAlternate=0x33d7976\n"
          "  --target NAME    probe 用哪条特征码定位目标（默认 CustomFileIdHook；\n"
          "                   另一条是 FileIdLookupFNV，实测更可能加载角色资源）\n"
          "  --mods DIR       自包含模式：直接扫这个模组目录（exe 自己换算 FileDataID，\n"
          "                   不需要 python、不需要预先生成 mappings\\files\n"
          "  --listfile PATH  与 --mods 配合；多个文件用 ';' 分隔\n"
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
    // 这份白名单是硬约束：漏写一个模式，那个模式就永远跑不起来。
    // 已经踩过两次：scout 和 mods 都写好了，但白名单没加，
    // 于是脚本一跑就被"未知模式"挡回去 —— 看起来像功能没做。
    // 加新模式时【必须同时改这里】。
    const std::vector<std::string> known = {"observe", "auto",   "hook",  "analyze",
                                            "diagnose", "sigscan", "probe", "scout",
                                            "patch",   "mods"};
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

  // 2b1) 模组加载模式（--mode mods）：这是本项目真正的目标。
  //
  // 与 patch / probe 的区别：
  //   patch 只做「第一半」—— 改掉 je，让客户端不去 CASC 取。
  //   probe 只做「旁路记录」—— 记下 id，不改返回值。
  //   mods  做【完整两半】—— 装 FileDataID 查表跳板 + 打 NoJump。
  //
  // 缺任何一半都不生效：只有 NoJump 时客户端会认为「CASC 没有、本地也没有」；
  // 只有跳板时客户端根本不会去查表。
  if (o.mode == "mods") {
    const std::string wowmod_dir = wowmod::join_path(o.workdir, "wowmod");
    CreateDirectoryW(utf8_to_wide(to_native_path(wowmod_dir)).c_str(), nullptr);
    const std::string log_path = wowmod::join_path(wowmod_dir, "wowmod-mods.txt");

    say("模组加载器：装 FileDataID 查表跳板 + 打 NoJump");
    std::printf("  这是 Arctium 机制的完整版：两半一起上。\n");
    std::printf("  数据来源: %s\\mappings\\*.txt + %s\\files\\\n\n",
                wowmod_dir.c_str(), wowmod_dir.c_str());
    std::fflush(stdout);

    // 默认逐字节照抄 Arctium。--stub native 才用本项目生成器
    // （16 字节表、命中直接 ret），后者已被 x64sim 验证但语义与 Arctium 不同。
    const auto kind = o.stub_native ? wowmod::win::StubKind::kNative
                                    : wowmod::win::StubKind::kArctium;
    std::printf("  跳板实现: %s\n\n", o.stub_native ? "native（本项目生成器）"
                                                     : "Arctium（逐字节照抄）");
    // 数据侧从哪里来：
    //   给了 --mods  ->  exe 自己扫模组目录 + listfile 换算 FileDataID
    //   否则        ->  读 <workdir>\wowmod\mappings + files（Arctium 磁盘形态）
    wowmod::win::ModLoaderResult r;
    if (!o.mods_dir.empty()) {
      const auto lfs = wowmod::win::split_listfiles(o.listfile_spec);
      if (lfs.empty()) {
        std::printf("\n[失败] --mods 需要同时给 --listfile（FileDataID 只能由 listfile 换算）\n");
        std::printf("       wowmod_loader.exe --mode mods --exe \"...\\Wow.exe\" \\\n");
        std::printf("           --mods \"D:\\Midnight Open Beta\\_midnight_\" \\\n");
        std::printf("           --listfile \"D:\\Midnight Open Beta\\_midnight_\\.lf\\wow-listfile.csv\"\n");
        std::printf("       （tools\\fetch-listfile.cmd 可以下载，约 147 MB，只需一次）\n\n");
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 2;
      }
      std::printf("  数据侧: 自包含扫描 %s（listfile %zu 个）\n", o.mods_dir.c_str(),
                  lfs.size());
      std::fflush(stdout);
      const auto sc = wowmod::win::build_selfcontained_mods(o.mods_dir, lfs);
      std::printf("    扫到文件 %zu, 解析出 FileDataID %zu（精确 %zu / _HD %zu / 文件名 %zu）\n",
                  sc.files_scanned, sc.matched, sc.by_exact, sc.by_hd, sc.by_name);
      if (sc.ambiguous || sc.missing)
        std::printf("    无法确定 %zu（其中重名 %zu）, 同 id 重复 %zu\n", sc.missing,
                    sc.ambiguous, sc.duplicates);
      for (size_t k = 0; k < sc.unresolved.size() && k < 8; ++k)
        std::printf("      未解析: %s\n", sc.unresolved[k].c_str());
      std::fflush(stdout);
      if (!sc.ok) {
        std::printf("\n[失败] %s\n", sc.error.c_str());
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 4;
      }
      wowmod::win::ModDataSet ds;
      ds.entries = sc.entries;
      // 自包含模式下 local_path 已经是绝对路径；files_dir 只用于报告。
      ds.files_dir = sc.game_root;
      ds.source_note = "--mods 自包含（" + std::to_string(sc.matched) + " 项）";
      r = wowmod::win::install_mod_loader_with_data(pi.hProcess, wowmod_dir, ds, o.wait_ms,
                                                    kind);
    } else {
      r = wowmod::win::install_mod_loader(pi.hProcess, wowmod_dir, o.wait_ms, kind);
    }
    const std::string text = wowmod::win::format_mod_loader_report(r);
    std::printf("\n%s", text.c_str());
    std::fflush(stdout);

    std::string werr;
    wowmod::write_text_file(log_path, text, &werr);
    std::printf("\n报告: %s\n", log_path.c_str());

    if (!r.ok) {
      std::printf("\n[失败] %s\n", r.error.c_str());
      std::printf("本次没有在客户端留下可用的模组加载器。\n");
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 4;
    }

    std::printf("\n[成功] 模组加载器已生效。\n");
    std::printf("  现在进游戏看角色模型 —— 这是第一次两半同时装上。\n");
    std::printf("  Ctrl+C 退出；关掉游戏所有改动自然消失（只改内存）。\n\n");
    std::fflush(stdout);

    if (o.detach) {
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 0;
    }
    // 等客户端退出，期间不碰任何东西
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    std::printf("客户端已退出（0x%08X）\n", code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
  }

  // 2b2) 侦察模式（--mode scout）：只报事实，【一个字节都不写】。
  //
  // 为什么需要它：前面几轮我们一直在猜「主模块基址是多少」「特征码命中
  // 落在哪个模块里」，猜错的代价是几轮往返。这个模式把事实一次性导出：
  //   主模块真实基址 / SizeOfImage / 明文比例
  //   每条特征码在【每个】模块里的命中地址
  //   两个目标 RVA 上现在的实际字节
  // 有了它，下一步不用猜。
  if (o.mode == "scout") {
    const std::string scout_dir = wowmod::join_path(o.workdir, "wowmod");
    CreateDirectoryW(utf8_to_wide(to_native_path(scout_dir)).c_str(), nullptr);
    const std::string scout_path = wowmod::join_path(scout_dir, "wowmod-scout.txt");
    std::printf("\n侦察模式：只读，不写客户端任何字节。\n");
    std::printf("  最多等待 %d 毫秒，期间持续观察解密进度。\n\n", o.wait_ms);

    std::string rep;
    rep += "wowmod 侦察报告（只读）\n";
    rep += "=======================================================\n\n";

    // ---- 1. 模块清单：名字 / 基址 / 大小 ----
    rep += "-- 已加载模块 --\n";
    {
      HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                             GetProcessId(pi.hProcess));
      if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
          do {
            char nm[512]{};
            WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, nm, sizeof(nm) - 1, nullptr, nullptr);
            char line[640];
            std::snprintf(line, sizeof(line), "  %-40s base=0x%llX size=0x%X\n", nm,
                          static_cast<unsigned long long>(
                              reinterpret_cast<uintptr_t>(me.modBaseAddr)),
                          me.modBaseSize);
            rep += line;
          } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
      } else {
        rep += "  （模块表不可用）\n";
      }
    }

    // ---- 2. 主模块与解密进度 ----
    const auto md = wowmod::win::dump_module_full(pi.hProcess, "", "");
    rep += "\n-- 主模块 --\n";
    {
      char line[512];
      if (!md.ok) {
        std::snprintf(line, sizeof(line), "  取主模块失败: %s\n", md.error.c_str());
        rep += line;
      } else {
        std::snprintf(line, sizeof(line), "  base = 0x%llX\n  SizeOfImage = 0x%zX\n",
                      static_cast<unsigned long long>(md.base), md.size_of_image);
        rep += line;
        std::snprintf(line, sizeof(line), "  明文页 %zu/%zu = %.1f%%\n", md.text_low_entropy,
                      md.text_checked,
                      md.text_checked ? 100.0 * static_cast<double>(md.text_low_entropy) /
                                            static_cast<double>(md.text_checked)
                                      : 0.0);
        rep += line;
        rep += "  节:\n";
        for (const auto& sec : md.sections) rep += "    " + sec + "\n";
      }
    }

    // ---- 3. 两个目标 RVA 上的现字节 ----
    rep += "\n-- 目标 RVA 现状（主模块内）--\n";
    if (md.ok) {
      struct Target { const char* name; uint32_t rva; };
      const Target targets[] = {
          {"LoadByFileIdAlternate.match", 0x33d7976},
          {"LoadByFileIdAlternate.je", 0x33d7977},
          {"LoadByFileIdAlternate.rel32", 0x33d7979},
          {"LoadByFilePathAlternate.match", 0x33d7b58},
          {"LoadByFilePathAlternate.je", 0x33d7b59},
          {"LoadByFilePathAlternate.rel32", 0x33d7b5b},
      };
      for (const auto& t : targets) {
        uint8_t buf[16]{};
        SIZE_T got = 0;
        const uint64_t va = md.base + t.rva;
        if (ReadProcessMemory(pi.hProcess, reinterpret_cast<const void*>(va), buf, sizeof(buf),
                              &got) &&
            got >= 8) {
          char line[256];
          std::snprintf(line, sizeof(line), "  %-32s rva=0x%X VA=0x%llX  %02X %02X %02X %02X | %02X %02X %02X %02X\n",
                        t.name, t.rva, static_cast<unsigned long long>(va), buf[0], buf[1],
                        buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
          rep += line;
        } else {
          char line[256];
          std::snprintf(line, sizeof(line), "  %-32s rva=0x%X  【读不到】\n", t.name, t.rva);
          rep += line;
        }
      }
    }

    // ---- 4. 特征码在所有模块里的命中 ----
    rep += "\n-- 特征码命中分布 --\n";
    auto pat_rep = wowmod::win::plan_branch_patches(pi.hProcess, {});
    rep += wowmod::win::format_branch_patch_report(pat_rep);

    rep += "\n以上均为只读结果，客户端未修改。\n";
    std::string werr;
    if (!wowmod::write_text_file(scout_path, rep, &werr))
      std::printf("  ！写报告失败: %s\n", werr.c_str());
    std::printf("%s\n", rep.c_str());
    std::printf("\n报告: %s\n", scout_path.c_str());
    std::printf("客户端保持运行。把这份报告发回来即可。\n");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
  }

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

  // 2c1) 【Arctium 机制】分支补丁模式。
  //
  //   这是 Arctium 真正用来让本地文件生效的做法，和我们前几轮做的
  //   「hook 查找函数 / 替换返回值」完全不是一回事：
  //
  //     memory.QueuePatch(Patterns.Windows.LoadByFileIdAlternate,
  //                       Patches.Windows.NoJump, "LoadByFileId", 3)
  //
  //   它把「按 FileDataID 从 CASC 加载」那条 je 改成【永不跳】，
  //   于是函数走空分支、返回 false，上层认为 CASC 里没有这个资源，
  //   转而去查 mappings/*.txt 里登记过的本地文件。
  //
  //   好处：只改 4 个字节，不搬指令、不装跳板、没有撕裂写入、
  //   也不碰任何函数入口 —— 前三次崩溃的原因（写不可执行页）在这里不存在。
  if (o.mode == "patch") {
    const std::string wowmod_dir = wowmod::join_path(o.workdir, "wowmod");
    CreateDirectoryW(utf8_to_wide(to_native_path(wowmod_dir)).c_str(), nullptr);
    const std::string log_path = wowmod::join_path(wowmod_dir, "wowmod-patch.txt");

    say("Arctium 分支补丁模式：关闭「从 CASC 加载」的条件跳转");

    // ---- 先确认数据侧有没有东西 ----
    //
    // 这一步是必须的：分支补丁本身只改变「客户端要不要去 CASC 加载」，
    // 它不会凭空产生本地文件。如果 wowmod\mappings 是空的，打上补丁的结果
    // 就是"客户端认为 CASC 里没有、本地也没有"—— 直接报文件缺失，
    // 比不打更糟。所以先查，查不到就明确告诉用户该先做什么。
    {
      namespace fs = std::filesystem;
      const std::string map_dir = wowmod::join_path(wowmod_dir, "mappings");
      const std::string files_dir = wowmod::join_path(wowmod_dir, "files");
      size_t map_files = 0, file_count = 0;
      std::error_code ec;
      if (fs::is_directory(std::filesystem::u8path(map_dir), ec)) {
        for (const auto& e : fs::directory_iterator(std::filesystem::u8path(map_dir), ec)) {
          if (e.is_regular_file(ec) &&
              e.path().extension() == std::filesystem::u8path(".txt"))
            ++map_files;
        }
      }
      if (fs::is_directory(std::filesystem::u8path(files_dir), ec)) {
        for (const auto& e : fs::recursive_directory_iterator(std::filesystem::u8path(files_dir), ec))
          if (e.is_regular_file(ec)) ++file_count;
      }
      std::printf("  数据检查: mappings\\*.txt %zu 个, files\\ %zu 个文件\n", map_files,
                  file_count);
      if (map_files == 0 || file_count == 0) {
        std::printf("\n[停止] 数据侧是空的，打补丁没有意义。\n");
        std::printf("  分支补丁只改变「客户端要不要去 CASC 加载」，它不会凭空产生本地文件。\n");
        std::printf("  现在打上去，客户端会认为 CASC 里没有、本地也没有 —— 直接报文件缺失。\n\n");
        std::printf("  请先跑 wowmod-mod.cmd 准备好这两样：\n");
        std::printf("    %s\\*.txt\n", map_dir.c_str());
        std::printf("    %s\\\n", files_dir.c_str());
        std::printf("  然后再回来跑本脚本。\n\n");
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 5;
      }
    }

    // ---- 等代码解密：不再用「两次相同就算稳定」----
    //
    // v15 之前的判据是「明文页数不再增长 -> 认为解密完成」。这个判据是错的，
    // 实测日志说明问题：
    //     明文页 10/260 = 3.8%
    //     明文页 22/260 = 8.5%
    //     明文页 22/260 = 8.5%   <- 连续两轮相同，于是判定"稳定"，开始扫描
    // 8.5% 的时候绝大多数 .text 还是密文，特征码扫到的是随机字节，
    // 所以同一个特征码三次跑出 10 处 / 2 处 / 1 处的不同结果，而且地址
    // （0x6F17976）连主模块范围都不在 —— 那不是代码，是密文里的巧合。
    //
    // 12.0.7 的 .text 是【按页惰性解密】：只有游戏真正执行到的页才会解密。
    // 所以正确做法不是"等一会儿"，而是：
    //   1) 等到明文比例超过阈值（默认 50%），或
    //   2) 用户自己把游戏开到能进游戏（加载过角色模型）之后再扫。
    // 选项 --wait-decrypt=<秒> 让用户把等待时间拉长到进入游戏之后。
    const unsigned kMinPlainPct = 50;
    bool ready = false;
    size_t best_low = 0;
    size_t last_checked = 0;
    int stable = 0;
    const DWORD ts = GetTickCount();
    for (int i = 0; i < 200; ++i) {
      const auto probe = wowmod::win::dump_module_full(pi.hProcess, "", "");
      if (probe.text_checked) {
        const size_t pct =
            probe.text_checked ? 100 * probe.text_low_entropy / probe.text_checked : 0;
        if (i % 2 == 0)
          std::printf("  等待代码解密... 明文页 %zu/%zu = %zu%% (需要 >= %u%%)\n",
                      probe.text_low_entropy, probe.text_checked, pct, kMinPlainPct);
        std::fflush(stdout);
        last_checked = probe.text_checked;
        if (probe.text_low_entropy > best_low) {
          best_low = probe.text_low_entropy;
          stable = 0;
        } else {
          ++stable;
        }
        // 两个条件都满足才算就绪：比例够高，且已经不再增长（避免半解密状态）。
        if (pct >= kMinPlainPct && stable >= 2) {
          ready = true;
          break;
        }
      }
      // 用户可以用 --wait-exit / 更长的 --wait 把窗口拉到进入游戏之后。
      if (GetTickCount() - ts > static_cast<DWORD>(o.wait_ms)) break;
      ::Sleep(1000);
    }
    if (!ready) {
      const size_t pct = last_checked ? 100 * best_low / last_checked : 0;
      std::printf("\n  [停止] 代码仍未解密到可用程度（明文 %zu/%zu = %zu%%，需要 >= %u%%）。\n",
                  best_low, last_checked, pct, kMinPlainPct);
      std::printf("  在密文上扫描得到的命中是随机字节，打上去会直接崩溃 —— 所以不打。\n\n");
      std::printf("  12.0.7 的 .text 是按页惰性解密的：只有游戏真正执行到的代码页才是明文。\n");
      std::printf("  所以判据不是\"等了多久\"，而是\"目标特征码有没有命中\"。\n");
      std::printf("  把等待时间加长可以让解密继续推进，例如：\n");
      std::printf("         wowmod_loader.exe --mode patch --apply --wait 600000\n\n");
      std::printf("  本次没有修改客户端任何字节。\n");
      std::string werr;
      wowmod::write_text_file(
          log_path,
          "分支补丁：未执行\n原因：代码未解密（明文 " + std::to_string(best_low) + "/" +
              std::to_string(last_checked) + "，需要 >= " + std::to_string(kMinPlainPct) +
              "%）\n在密文上扫描的命中不可信，已拒绝写入。\n",
          &werr);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 6;
    }
    std::printf("  代码已解密到可用程度（明文 %zu，>= %u%%）\n", best_low, kMinPlainPct);

    say("定位分支补丁点（只读，不写入）");
    std::map<std::string, uint32_t> rva_map;
    for (const auto& kv : o.patch_rva) rva_map[kv.first] = kv.second;
    if (!rva_map.empty())
      std::printf("  使用 --rva 点名 %zu 条（跳过自动判定）\n", rva_map.size());
    auto rep = wowmod::win::plan_branch_patches(pi.hProcess, rva_map);
    std::string report = wowmod::win::format_branch_patch_report(rep);
    std::printf("%s", report.c_str());
    std::fflush(stdout);

    if (!rep.ok) {
      std::printf("\n[失败] %s\n", rep.error.c_str());
      std::printf("本次没有修改客户端任何字节。\n");
      // 自动判定拒绝时，给出可执行的下一步，而不是让用户干等。
      std::printf("\n  如果某条是「同一段代码被映射多份」而跳过，可以用 --rva 点名:\n");
      for (const auto& pp : rep.patches) {
        if (pp.error.find("映射多份") == std::string::npos) continue;
        std::printf("    --rva %s=<RVA>    （该条在本次扫描里命中的 RVA 见上面报告）\n",
                    pp.name.c_str());
      }
      std::string werr;
      wowmod::write_text_file(log_path, report + "\n[失败] " + rep.error + "\n", &werr);
      std::printf("报告: %s\n", log_path.c_str());
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 4;
    }

    if (o.dry_run) {
      std::printf("\n[演练] 目标都已通过唯一性 + 字节校验，但【没有写入】。\n");
      std::printf("  要真正打补丁请加 --apply（会在客户端留下 4 字节改动）。\n");
      std::string werr;
      wowmod::write_text_file(log_path, report + "\n[演练] 未写入\n", &werr);
      std::printf("报告: %s\n", log_path.c_str());
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 0;
    }

    say("写入分支补丁");
    if (!wowmod::win::apply_branch_patches(pi.hProcess, &rep)) {
      std::printf("\n[失败] 写入没有成功：%s\n", rep.error.c_str());
      report = wowmod::win::format_branch_patch_report(rep);
      std::printf("%s", report.c_str());
      std::string werr;
      wowmod::write_text_file(log_path, report + "\n[失败] " + rep.error + "\n", &werr);
      std::printf("报告: %s\n", log_path.c_str());
      // 已经改过的那些会被 apply 内部回滚，这里再兜一次底。
      std::string rerr;
      wowmod::win::revert_branch_patches(pi.hProcess, &rep, &rerr);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 4;
    }

    report = wowmod::win::format_branch_patch_report(rep);
    std::printf("\n%s", report.c_str());
    std::fflush(stdout);
    {
      std::string werr;
      wowmod::write_text_file(log_path, report, &werr);
      std::printf("报告: %s\n", log_path.c_str());
    }

    std::printf("\n  补丁已生效。现在进游戏看角色模型是否变成你放的贴图。\n");
    std::printf("  客户端退出后补丁自动消失（只改内存，不动磁盘文件）。\n\n");
    std::fflush(stdout);

    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    return 0;
  }

  // 2c2) 旁路记录模式：定位 FileDataID 查找函数，装上「只记录」的跳板。
  //
  //   为什么先做这一步而不是直接替换返回值：
  //     我们已确证 0x33e06a0 是 CAS.cpp 里 edx=FileDataID 的哈希查找函数
  //     （Arctium 的 CustomFileIdHook 唯一 8/8 语义命中点）。但它的返回值
  //     那个对象 +0x10 处到底是什么结构，我们还没有证据。直接替换 = 拿垃圾
  //     指针当资源用，客户端必崩。
  //
  //   所以第一版 hook 只做「记下 edx 就跳回去」：控制流与原始代码等价，
  //   不改任何寄存器结果。拿到真实调用序列之后，才知道该给哪些 id 做替换、
  //   以及返回值该长什么样。
  if (o.mode == "probe") {
    bool g_client_died = false;
    wowmod::win::CrashEvidence g_crash;
    int probe_round = 0;
    const std::string wowmod_dir = wowmod::join_path(o.workdir, "wowmod");
    CreateDirectoryW(utf8_to_wide(to_native_path(wowmod_dir)).c_str(), nullptr);
    const std::string log_path = wowmod::join_path(wowmod_dir, "wowmod-probe.txt");

    say("旁路记录模式：定位 FileDataID 查找函数并安装只读探针");
    std::printf("  这一步会在客户端里写 14 字节跳转 + 一段跳板，\n"
                "  但【不改变任何返回值、不改变控制流语义】，只是把传入的 id 记下来。\n\n");

    // ---- 等代码解密，与 sigscan 同一判据 ----
    size_t best_low = 0;
    int stable = 0;
    const DWORD ts = GetTickCount();
    for (int i = 0; i < 200; ++i) {
      // 探测模式只关心"函数所在页解出来没有"，不需要每轮采样 256 页 ——
      // 跨进程读 64 个页会明显拖慢刚启动的客户端。这里每 3 轮采一次。
      if (i % 3 != 0) { ::Sleep(1000); continue; }
      const auto probe = wowmod::win::dump_module_full(pi.hProcess, "", "");
      if (probe.text_checked) {
        if (i % 6 == 0)
          std::printf("  等待代码解密... 明文页 %zu/%zu = %.1f%%\n", probe.text_low_entropy,
                      probe.text_checked,
                      100.0 * static_cast<double>(probe.text_low_entropy) /
                          static_cast<double>(probe.text_checked));
        std::fflush(stdout);
        if (probe.text_low_entropy > best_low) {
          best_low = probe.text_low_entropy;
          stable = 0;
        } else if (++stable >= 3 && best_low > 0) {
          break;
        }
      }
      if (GetTickCount() - ts > static_cast<DWORD>(o.wait_ms)) break;
      ::Sleep(1000);
    }

    // ---- 用特征码现找目标（0x33e06a0 是 RVA，基址每次启动都变，不能写死）----
    say("按 CustomFileIdHook 特征码定位目标");
    const auto res = wowmod::win::scan_arctium_signatures(pi.hProcess, o.exe);
    uint64_t target = 0;
    int best_score = 0;
    bool best_image = false;
    bool best_rx = false;
    std::printf("  候选（语义分 / 是否可执行 / 区域类型）：\n");
    std::printf("  目标特征码: %s\n", o.probe_sig.c_str());
    for (const auto& h : res.hits) {
      if (h.name != o.probe_sig) continue;
      std::printf("    0x%s  语义 %d/8  %s  %s  RVA 0x%s  Protect 0x%lx\n",
                  wowmod::to_hex(h.match_va, 16).c_str(), h.semantic_score,
                  h.has_rx ? "可执行" : "【不可执行·不能用】",
                  h.image_backed ? "MEM_IMAGE(模块本体)"
                                 : (h.region_type == 0x40000 ? "MEM_MAPPED(映射视图)" : "私有内存"),
                  wowmod::to_hex(h.image_rva, 16).c_str(),
                  static_cast<unsigned long>(h.region_protect));
      // 选优顺序：语义分 > 可执行（硬条件）> 模块本体 > 先出现的
      //
      // 上一版只看 "语义分 + 是否 MEM_IMAGE"，结果挑中了一处 Protect=0x04
      // （PAGE_READWRITE，根本不可执行）的映射页 —— 跳转写进了一块数据页，
      // 客户端执行不到它，而那块数据页本身可能被壳当成校验数据。
      const bool better = (h.semantic_score > best_score) ||
                          (h.semantic_score == best_score && h.has_rx && !best_rx);
      if (better) {
        best_score = h.semantic_score;
        best_image = h.image_backed;
        best_rx = h.has_rx;
        target = h.match_va;
      }
    }
    if (target && !best_rx) {
      std::printf("\n  [拒绝] 唯一可用的候选所在页不可执行（Protect 不含 PAGE_EXECUTE*）。\n"
                  "         往不可执行的页上写跳转是无意义的，而且可能破坏壳的数据。\n"
                  "         本次不安装任何东西。\n");
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 4;
    }
    const int min_score = (o.probe_sig == "CustomFileIdHook") ? 8 : 0;
    if (!target || best_score < min_score) {
      std::printf("  [失败] 特征码 %s 没有找到可用目标（最高语义分 %d/8）\n",
                  o.probe_sig.c_str(), best_score);
      std::printf("  含义：本轮扫过的字节里不含这段代码（范围没覆盖到，或该页还没解密）。\n");
      std::printf("  本次没有修改客户端任何字节。\n");
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 4;
    }
    std::printf("  [成功] 目标 0x%s（语义分 %d/8，%s）\n",
                wowmod::to_hex(target, 16).c_str(), best_score,
                best_image ? "模块本体，写入安全" : "映射视图，写入可能影响共享映射");

    // ---- 把所有候选附近的字节 dump 到文件（崩溃后分析用，只读）----
    //
    // 前三次失败最大的问题不是"崩了"，而是"崩了之后我们手上没有任何证据能说明
    // 我们到底改的是哪块内存"。这里把每处候选前后各 128 字节写到文件，
    // 即使客户端崩了，我们也能离线对比两处命中的差异。
    {
      const std::string hp = wowmod::join_path(wowmod_dir, "probe-hits.txt");
      std::string dump;
      char line[256];
      for (const auto& h : res.hits) {
        if (h.name != "CustomFileIdHook") continue;
        std::snprintf(line, sizeof(line),
                      "== 0x%s  语义 %d/8  区域 %s  Protect 0x%lx  可执行=%s\n",
                      wowmod::to_hex(h.match_va, 16).c_str(), h.semantic_score,
                      h.image_backed ? "MEM_IMAGE"
                                     : (h.region_type == 0x40000 ? "MEM_MAPPED" : "PRIVATE"),
                      static_cast<unsigned long>(h.region_protect), h.has_rx ? "是" : "否");
        dump += line;
        const uint64_t from = h.match_va > 128 ? h.match_va - 128 : h.match_va;
        std::vector<uint8_t> buf(384, 0);
        SIZE_T got = 0;
        if (ReadProcessMemory(pi.hProcess, reinterpret_cast<const void*>(from), buf.data(),
                              buf.size(), &got) && got > 0) {
          for (size_t i = 0; i < got; i += 16) {
            std::snprintf(line, sizeof(line), "  %012llx  ",
                          static_cast<unsigned long long>(from + i));
            dump += line;
            for (size_t k = 0; k < 16 && i + k < got; ++k) {
              std::snprintf(line, sizeof(line), "%02X ", buf[i + k]);
              dump += line;
            }
            dump += "\n";
          }
        } else {
          dump += "  （该区域读不出来）\n";
        }
        dump += "\n";
      }
      std::string werr2;
      wowmod::write_text_file(hp, dump, &werr2);
      std::printf("  候选字节已导出: %s\n", hp.c_str());
    }

    // ---- 写入前一致性验证 ----
    //
    // 扫描是一次读取，安装是另一次写入，中间客户端的壳可能已经重新映射/解密过
    // 这块内存。所以装之前必须重新读一遍，确认起始字节仍是目标函数的序言。
    // 不一致 = 这块内存已经不是我们分析时的那份代码，绝不能写。
    {
      // 两个目标的序言不同，按实际选择的特征码校验
      std::vector<uint8_t> kPrologue;
      if (o.probe_sig == "FileIdLookupFNV") {
        kPrologue = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48, 0x89, 0x7C};
      } else {
        kPrologue = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xF9};
      }
      uint8_t now[13];
      SIZE_T got = 0;
      const bool ok = ReadProcessMemory(pi.hProcess,
                                        reinterpret_cast<const void*>(target), now,
                                        sizeof(now), &got) && got == sizeof(now);
      if (!ok) {
        std::printf("  [拒绝] 安装前读取目标地址失败，不安装。\n");
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 4;
      }
      bool same = true;
      for (size_t i = 0; i < sizeof(now); ++i) {
        if (now[i] != kPrologue[i]) { same = false; break; }
      }
      if (!same) {
        std::printf("  [拒绝] 目标地址的字节和我们扫描时不一致：\n");
        std::printf("         期望 ");
        for (uint8_t v : kPrologue) std::printf("%02X ", v);
        std::printf("\n         实际 ");
        for (size_t i = 0; i < sizeof(now); ++i) std::printf("%02X ", now[i]);
        std::printf("\n         说明这块内存已被壳重新映射或解密过，不能写。\n");
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 4;
      }
      std::printf("  [校验] 目标序言与扫描时一致（13 字节），可以安全安装\n");
    }

    // ---- 装探针 ----
    wowmod::win::FileIdHook hook;
    hook.set_process(pi.hProcess);
    wowmod::win::InstallReport rep;
    say("安装旁路探针");
    if (!hook.install_probe(pi.hProcess, target, "edx", 4096, &rep)) {
      std::printf("  [失败] %s\n", rep.error.c_str());
      for (const auto& s : rep.steps) std::printf("    %s\n", s.c_str());
      std::printf("  本次没有留下任何改动。\n");
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 4;
    }
    for (const auto& s : rep.steps) std::printf("    %s\n", s.c_str());
    std::printf("  环形缓冲 0x%s，跳板 0x%s，trampoline 0x%s\n",
                wowmod::to_hex(rep.id_table_va, 16).c_str(),
                wowmod::to_hex(rep.stub_va, 16).c_str(),
                wowmod::to_hex(rep.trampoline_va, 16).c_str());
    std::printf("\n  探针已生效。现在请在游戏里【正常玩一会儿】——\n"
                "    切角色、进世界、开角色面板/幻化/理发店、进出场景。\n"
                "  每 2 秒会读一次记录，最长监控 %d ms（--wait 可改）。\n"
                "  按 Ctrl+C 或等它自己结束，日志在：\n    %s\n\n",
                o.wait_ms, log_path.c_str());

    // ---- 轮询 ----
    uint32_t last_seq = 0;
    uint32_t logged = 0;
    bool first = true;
    const DWORD t0 = GetTickCount();
    while (GetTickCount() - t0 < static_cast<DWORD>(o.wait_ms)) {
      std::vector<wowmod::win::ProbeRecord> recs;
      std::string err;
      if (wowmod::win::read_probe_records(pi.hProcess, rep.id_table_va, 4096, &last_seq, &recs,
                                          &err)) {
        if (!recs.empty()) {
          logged += static_cast<uint32_t>(recs.size());
          wowmod::win::append_probe_log(log_path, recs, last_seq, first);
          first = false;
          const auto agg = wowmod::win::summarize(recs);
          std::printf("  [+%zu 条，累计 %u] 最近 id:", recs.size(), logged);
          const size_t show = agg.size() < 6 ? agg.size() : 6;
          for (size_t i = 0; i < show; ++i)
            std::printf(" %u", agg[i].first);
          std::printf("\n");
          std::fflush(stdout);
        }
      } else if (err.find("magic") != std::string::npos) {
        // 缓冲区 magic 不符通常意味着跳板还没被执行过，属正常早期状态
      }
      // 每轮都查：① 进程还活着吗 ② 有没有新产生的崩溃转储。
      //
      // 上一版只在"进程退出"时才查崩溃 —— 但客户端的 Fatal Error 是
      // 【弹窗卡住进程】，进程仍然存活，于是永远查不到，用户什么判定都看不到。
      // 现在改成只要发现新的 c00000e5 转储，立刻收工并给判定。
      DWORD code = 0;
      if (!GetExitCodeProcess(pi.hProcess, &code) || code != STILL_ACTIVE) {
        std::printf("\n  ！客户端已退出（exit code 0x%08X）\n", code);
        g_client_died = true;
        break;
      }
      if (probe_round++ % 2 == 0) {
        const auto ev = wowmod::win::find_latest_illegal_instruction_crash(o.workdir);
        if (ev.found && ev.exception_code == 0xC00000E5u) {
          std::printf("\n  ！检测到崩溃：客户端弹出了 Fatal Error（进程还在，但已不可用）\n");
          g_crash = ev;
          break;
        }
      }
      ::Sleep(2000);
    }

    // ---- 崩溃取证：客户端如果死了，判定崩溃点是不是我们改的字节 ----
    if (g_client_died || g_crash.found || logged == 0) {
      const auto ev = g_crash.found
                          ? g_crash
                          : wowmod::win::find_latest_illegal_instruction_crash(o.workdir);
      std::vector<std::pair<uint64_t, uint64_t>> hooked = {{target, target + 14}};
      std::vector<std::pair<uint64_t, uint64_t>> stubs = {
          {rep.stub_va, rep.stub_va + 0x200},
          {rep.trampoline_va, rep.trampoline_va + 0x100}};
      const int verdict = wowmod::win::classify_crash_address(ev, hooked, stubs);
      std::printf("\n== 崩溃现场判定 ==\n");
      std::printf("%s", wowmod::win::describe_crash_verdict(ev, verdict).c_str());
      if (g_client_died || g_crash.found)
        std::printf("  说明: 本次 hook 区间 [0x%s, 0x%s)，跳板 0x%s，trampoline 0x%s\n",
                    wowmod::to_hex(target, 16).c_str(),
                    wowmod::to_hex(target + 14, 16).c_str(),
                    wowmod::to_hex(rep.stub_va, 16).c_str(),
                    wowmod::to_hex(rep.trampoline_va, 16).c_str());
    }

    std::printf("\n  本次共记录 %u 次调用。\n", logged);
    if (logged == 0)
      std::printf("  ！一条都没记到。说明目标函数在这段时间里没被调用 ——\n"
                  "    请确认打进了游戏世界、并且打开了角色面板/幻化界面。\n");
    std::printf("  日志: %s\n", log_path.c_str());
    if (!g_client_died) {
      std::printf("\n  卸载探针（把原始字节写回）...\n");
      if (hook.remove()) std::printf("  已卸载，客户端恢复原状。\n");
      else std::printf("  ！卸载失败，请直接结束客户端进程。\n");
    } else {
      std::printf("  客户端已退出，无需卸载。\n");
    }
    std::printf("  本次没有改变客户端的行为，只记录了调用。\n");
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
    //
    // 教训（v4 实测）：只等 "CASC" 这类标记串出现是【假就绪】——标记串在
    // .rdata 里，客户端一起来就能读到，但那时代码段才解密了 11.9%。
    // 特征码全在 .text 里，扫得太早就必然 0 命中（CustomFileIdHook 就是这么漏的）。
    // 所以这里改成等【可执行段明文比例】稳定，与 --dump-module 用同一判据。
    bool ready = false;
    size_t best_low = 0;
    int stable = 0;
    const DWORD ts = GetTickCount();
    for (int i = 0; i < 200; ++i) {
      const auto probe = wowmod::win::dump_module_full(pi.hProcess, "", "");
      if (probe.text_checked) {
        const double pct = 100.0 * static_cast<double>(probe.text_low_entropy) /
                           static_cast<double>(probe.text_checked);
        if (i % 2 == 0)
          std::printf("  等待代码解密... 明文页 %zu/%zu = %.1f%%\n",
                      probe.text_low_entropy, probe.text_checked, pct);
        std::fflush(stdout);
        if (probe.text_low_entropy > best_low) {
          best_low = probe.text_low_entropy;
          stable = 0;
        } else if (++stable >= 3 && best_low > 0) {
          std::printf("  解密比例已稳定，开始扫描。\n");
          ready = true;
          break;
        }
      }
      if (GetTickCount() - ts > static_cast<DWORD>(o.wait_ms)) break;
      ::Sleep(1000);
    }
    if (!ready)
      std::printf("  ！等到上限仍未稳定（当前明文页 %zu），仍会继续扫描。\n", best_low);

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
          std::printf("  ！明文只有 %.1f%%，偏少（客户端还没执行到那么多代码页）。\n",
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
            std::printf("  拦截记录已开始；按回车停止记录。\n");
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
    // 运行时线程在客户端进程内继续工作（写报告、等客户端窗口、按热键）。
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
    say("报告: " + wowmod::join_path(o.workdir, "wowmod\\wowmod-analysis.txt"));
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
