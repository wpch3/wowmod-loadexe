// wowmod_rt.dll —— 在客户端【内部】完成分析 + 安装 FileDataID loose-file hook。
//
// 为什么需要它（以及为什么它比外部注入更可靠）：
//   * Firestorm 的加载壳会把真正的客户端代码解密到内存里，磁盘上的 exe/.text 是密文。
//     任何「先静态扫特征再打补丁」的启动器都拿不到真实代码，只能靠猜。
//   * 本 DLL 一旦进入进程，看到的就是解密后的映像：字符串在、函数在、指令在。
//     于是可以现场做交叉引用分析（analyze），把候选 hook 点算出来。
//   * 但仍然不在「猜到的地址」上自动打补丁：默认进入观察模式，
//     把分析结果写到服务器目录下的 wowmod-analysis.json，
//     由用户按热键（默认 F8）在确认后安装。
//
// 工作模式（环境变量 WOWMOD_RT_MODE）：
//   observe  （默认）只分析并写报告，不修改客户端任何字节
//   auto     分析后自动安装第一个可用的 hook 点（日志会完整记录每一步）
//
// 其它环境变量 / 命令：
//   WOWMOD_RT_FILES=folder;folder     本地文件根目录（默认 <游戏目录>/wowmod/files）
//   WOWMOD_RT_MAP=file1;file2         listfile 映射（默认 <游戏目录>/wowmod/mappings/*.txt）
//   WOWMOD_RT_IDREG=rdx               FileDataID 所在寄存器
//   WOWMOD_RT_HOTKEY=0x77            安装热键（0 = 关闭；默认 F8）
//   WOWMOD_RT_AUTOTRIGGER=1          登录界面出现后自动安装（默认 1，仅 auto 模式生效）
//   WOWMOD_RT_HOOK_RVA=0x1234        跳过分析，直接用指定 RVA（高级）
//
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include <windows.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "windows/detour.hpp"
#include "windows/fd_hook.hpp"
#include "windows/scan_images.hpp"
#include "wowmod/analyze.hpp"
#include "wowmod/json.hpp"
#include "wowmod/mapping.hpp"
#include "wowmod/util.hpp"
#include "wowmod/xref.hpp"

namespace {

using namespace wowmod;

// ---- 运行状态 ----
struct State {
  HMODULE self = 0;
  uint64_t image_base = 0;
  uint64_t analysis_base = 0;
  size_t image_size = 0;
  std::string module_path;
  AnalyzeResult analysis;
  win::FileIdHook hook;
  std::vector<win::Detour> intercept_detours;
  std::vector<win::RemoteBlock> intercept_stubs;
  win::RemoteBlock intercept_counter;
  win::RemoteBlock intercept_ring;
  bool intercepting = false;
  uint64_t last_intercept_seq = 0;
  std::string intercept_log;
  std::vector<std::pair<uint64_t, std::string>> entries;
  bool installed = false;
  bool triggered = false;
  std::string log_path;
  std::string report_path;
  std::string files_dir;
  std::string id_register = "rdx";
  std::string return_register = "rax";
  std::string mode = "observe";
  uint64_t forced_hook_rva = 0;
  bool auto_trigger = true;
  bool started = false;
  bool init_called = false;
  UINT hotkey = VK_F8;
};
State g;

// ---- 日志（始终写文件，因为客户端会吃掉 stdout） ----
void log_line(const std::string& s) {
  const std::string line = "[" + to_hex(GetTickCount64(), 8) + "] " + s + "\n";
  OutputDebugStringA(("[wowmod_rt] " + s + "\n").c_str());
  if (g.log_path.empty()) return;
  HANDLE h = CreateFileW(utf8_to_wide(to_native_path(g.log_path)).c_str(), FILE_APPEND_DATA,
                         FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return;
  DWORD wrote = 0;
  WriteFile(h, line.data(), static_cast<DWORD>(line.size()), &wrote, nullptr);
  CloseHandle(h);
}

std::string env_str(const wchar_t* name) {
  DWORD n = GetEnvironmentVariableW(name, nullptr, 0);
  if (n == 0) return "";
  std::wstring buf(n, L'\0');
  GetEnvironmentVariableW(name, buf.data(), n);
  while (!buf.empty() && buf.back() == L'\0') buf.pop_back();
  return wide_to_utf8(buf);
}

uint64_t env_hex(const wchar_t* name, uint64_t def) {
  const std::string s = env_str(name);
  if (s.empty()) return def;
  uint64_t v = 0;
  if (!parse_u64(s, &v, 0)) return def;
  return v;
}

// ---- 主模块信息 ----
bool main_module_info(std::string* path_out, uint64_t* base, size_t* size) {
  wchar_t buf[MAX_PATH * 4] = {0};
  const DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
  if (!n) return false;
  if (path_out) *path_out = wide_to_utf8(std::wstring(buf, n));
  HMODULE m = GetModuleHandleW(nullptr);
  const uint8_t* p = reinterpret_cast<const uint8_t*>(m);
  if (!p || p[0] != 'M' || p[1] != 'Z') return false;
  const uint32_t lfanew = *reinterpret_cast<const uint32_t*>(p + 0x3C);
  const uint16_t magic = *reinterpret_cast<const uint16_t*>(p + lfanew + 24);
  const size_t opt = lfanew + 24;
  const uint32_t size_of_image =
      *reinterpret_cast<const uint32_t*>(p + opt + (magic == 0x10B ? 56 : 56));
  if (base) *base = reinterpret_cast<uint64_t>(m);
  if (size) *size = size_of_image;
  return true;
}

// ---- 载入映射表 ----
void load_mappings(const std::string& game_dir, MappingTable* table) {
  const std::string env = env_str(L"WOWMOD_RT_MAP");
  std::vector<std::string> files;
  if (!env.empty()) {
    for (const auto& part : split(env, ';'))
      if (!part.empty()) files.push_back(part);
  } else {
    const std::string dir = join_path(join_path(game_dir, "wowmod"), "mappings");
    std::string err;
    for (const auto& rel : list_files_recursive(dir, &err))
      if (ends_with(to_lower(rel), ".txt")) files.push_back(join_path(dir, rel));
  }
  Diagnostics diag;
  for (const auto& f : files) {
    table->load_file(f, &diag);
    log_line("映射表已载入: " + f);
  }
  if (files.empty())
    log_line("未找到任何 listfile 映射（" + std::to_string(table->size()) + " 条）");
}

// ---- 枚举本地文件，生成 id -> 绝对路径 ----
void load_entries(const std::string& files_dir, const MappingTable& maps,
                  std::vector<std::pair<uint64_t, std::string>>* out) {
  out->clear();
  std::string err;
  const auto files = list_files_recursive(files_dir, &err);
  if (!err.empty()) {
    log_line("枚举 files 目录失败: " + err);
    return;
  }
  std::vector<std::string> sorted = files;  // list_files_recursive 已排序，这里再保证一次
  std::sort(sorted.begin(), sorted.end());
  std::vector<std::string> unmapped;
  for (const auto& rel : sorted) {
    const auto id = maps.id_for_path(rel);
    if (!id) {
      unmapped.push_back(rel);
      continue;
    }
    const std::string abs = to_native_path(absolute_path(join_path(files_dir, rel)));
    out->push_back({static_cast<uint64_t>(*id), abs});
  }
  log_line("files 目录扫描: " + std::to_string(sorted.size()) + " 个文件, " +
           std::to_string(out->size()) + " 个映射到 FileDataID, " +
           std::to_string(unmapped.size()) + " 个未映射");
  for (const auto& u : unmapped) log_line("  未映射: " + u);
}

// ---- 分析 ----
// 关键：不看"模块基址"，而是枚举整个进程的内存区域。
// Firestorm 把真实客户端解密到独立分配里（见 scan_images.hpp 的说明），
// 只扫主模块会一无所获。
void run_analysis() {
  log_line("开始枚举进程内候选映像（不只主模块）");
  const auto images = win::scan_process_images(GetCurrentProcess(), 256u << 20);
  log_line("候选映像 " + std::to_string(images.size()) + " 个");

  size_t best = SIZE_MAX;
  for (size_t i = 0; i < images.size(); ++i) {
    const auto& im = images[i];
    if (im.marker_hits == 0) continue;
    log_line("  [" + std::to_string(i) + "] 0x" + to_hex(im.base, 16) + " " +
             std::to_string(im.committed_bytes / 1048576) + " MB" +
             (im.module_name.empty() ? " (匿名分配)" : " (" + im.module_name + ")") +
             " 标记命中 " + std::to_string(im.marker_hits) + " [" + im.first_marker + "]");
    if (best == SIZE_MAX) best = i;
  }
  if (best == SIZE_MAX) {
    log_line("没有任何候选映像包含 loose-file 标记字符串。");
    log_line("这通常意味着：客户端还没解密完，或者被剥掉了字符串。");
    log_line("已写出候选清单，请把报告发出来。");
    // 仍然把候选写入报告，便于判断
    Json list = Json::make_array();
    for (const auto& im : images) {
      Json o = Json::make_object();
      o.set("base", Json::make_string(to_hex(im.base, 16)));
      o.set("size", Json::make_number(static_cast<double>(im.committed_bytes)));
      o.set("executable", Json::make_bool(im.executable));
      o.set("peHeader", Json::make_bool(im.has_pe_header));
      o.set("module", Json::make_string(im.module_name));
      o.set("markerHits", Json::make_number(static_cast<double>(im.marker_hits)));
      list.push(o);
    }
    write_text_file(g.report_path + ".json", list.dump(2), nullptr);
    g.analysis.ok = false;
    g.analysis.error = "未找到含标记字符串的映像";
    return;
  }

  const auto& target = images[best];
  log_line("选用映像 0x" + to_hex(target.base, 16) + " 作为客户端主数据");
  ImageView img;
  img.data = target.bytes.data();
  img.size = target.bytes.size();
  img.base_va = target.base;
  AnalyzeOptions opt;
  opt.max_functions = 24;
  g.analysis = analyze_image(img, opt);
  g.analysis_base = target.base;
  log_line("分析完成: 字符串命中 " + std::to_string(g.analysis.string_hits.size()) +
           " 个, hook 点方案 " + std::to_string(g.analysis.sites.size()) +
           " 个, 推荐 detour " + std::to_string(g.analysis.detour_targets.size()) +
           " 个, id 查找候选 " + std::to_string(g.analysis.id_candidates.size()) + " 个");
  log_line("提示: 报告里的 RVA 都是相对 0x" + to_hex(target.base, 16) + " 的偏移");
}

// ---- 写报告（同时写文本与 JSON，便于直接贴回聊天） ----
void write_report() {
  if (g.report_path.empty()) return;
  std::string text = "wowmod 运行时分析报告\n";
  text += "客户端: " + g.module_path + "\n";
  text += "主模块基址: 0x" + to_hex(g.image_base, 16) + "\n";
  text += "分析基址: 0x" + to_hex(g.analysis_base, 16) + "  映像大小: " +
          std::to_string(g.image_size / 1048576) + " MB\n";
  text += "模式: " + g.mode + "   id 寄存器: " + g.id_register + "\n\n";
  text += g.analysis.to_text();
  write_text_file(g.report_path, text, nullptr);
  write_text_file(g.report_path + ".json", g.analysis.to_json().dump(2), nullptr);
  log_line("报告已写入: " + g.report_path);
}

// ---- 安装 ----
size_t pick_hook_rva() {
  if (g.forced_hook_rva) return static_cast<size_t>(g.forced_hook_rva);
  // 优先选「紧邻 loose-file 相关字符串引用」且可 hook 的函数
  for (const auto& s : g.analysis.sites) {
    if (s.site.ok) return s.function_rva;
  }
  return SIZE_MAX;
}

bool install_now(const char* why) {
  if (g.installed || g.intercepting) {
    log_line("hook 已安装，忽略重复请求");
    return true;
  }
  const size_t rva = pick_hook_rva();

  // 模式 B（默认）：拦截所有「引用 loose-file 标记字符串」的函数，只记录不改变行为。
  if (g.mode != "hook" || rva == SIZE_MAX) {
    if (g.analysis.detour_targets.empty()) {
      log_line(std::string("安装被拒绝（") + why +
               "）: 分析没有找到任何可拦截的函数。请把报告发出来，用 WOWMOD_RT_HOOK_RVA 手动指定。");
      return false;
    }
    std::vector<win::InterceptTarget> targets;
    const size_t limit = std::min<size_t>(g.analysis.detour_targets.size(), 8);
    for (size_t i = 0; i < limit; ++i) {
      const auto& t = g.analysis.detour_targets[i];
      if (!t.hookable) continue;
      win::InterceptTarget it;
      it.target = g.analysis_base + t.function_rva;
      it.tag = t.marker;
      targets.push_back(it);
      log_line("拦截目标: 0x" + to_hex(it.target, 16) + " [" + t.marker + "]");
    }
    if (targets.empty()) {
      log_line("安装被拒绝: 所有候选函数都不可 hook");
      return false;
    }
    std::string err;
    // 记录用的计数器与环形缓冲由 DLL 自己持有，便于热键线程持续读出。
    g.intercept_counter = win::RemoteBlock(GetCurrentProcess(), 8, PAGE_READWRITE);
    g.intercept_ring = win::RemoteBlock(GetCurrentProcess(), 64 * win::InterceptRecord::kSize,
                                        PAGE_READWRITE);
    if (!g.intercept_counter.ok() || !g.intercept_ring.ok()) {
      log_line("安装拦截失败: 分配记录缓冲失败");
      return false;
    }
    const uint64_t zero = 0;
    win::write_remote(GetCurrentProcess(),
                      reinterpret_cast<uint64_t>(g.intercept_counter.addr()), &zero, 8, nullptr,
                      false);
    if (!win::install_interceptors(GetCurrentProcess(), targets, g.intercept_log,
                                   reinterpret_cast<uint64_t>(g.intercept_counter.addr()),
                                   reinterpret_cast<uint64_t>(g.intercept_ring.addr()), 64,
                                   &g.intercept_detours, &g.intercept_stubs, &err)) {
      log_line("安装拦截失败: " + err);
      win::remove_interceptors(GetCurrentProcess(), &g.intercept_detours, &g.intercept_stubs);
      return false;
    }
    g.intercepting = true;
    log_line("拦截已生效（" + std::string(why) + "）: " + std::to_string(targets.size()) +
             " 个函数。现在去登录界面/进游戏，每次这些函数被调用都会记录参数。");
    log_line("记录文件: " + g.intercept_log);
    log_line("跑完一轮后，把 wowmod-intercept.log 发出来即可确定 FileDataID 在哪个参数、返回什么。");
    return true;
  }

  // 模式 C：按用户确认的方式打 FileDataID 重定向补丁。
  if (g.entries.empty()) {
    log_line(std::string("安装被拒绝（") + why + "）: 没有可用的 FileDataID 映射条目");
    return false;
  }
  if (rva == SIZE_MAX) {
    log_line("安装被拒绝: 没有可用的 hook 点（需要 WOWMOD_RT_HOOK_RVA）");
    return false;
  }
  win::InstallRequest req;
  req.hook_target = g.analysis_base + rva;
  req.id_register = g.id_register;
  req.return_register = g.return_register;
  req.entries = g.entries;
  req.min_cover = 14;

  log_line("开始安装 FileDataID hook（" + std::string(why) + "）: target=0x" +
           to_hex(req.hook_target, 16) + " rva=0x" + to_hex(rva, 1) +
           " 条目=" + std::to_string(g.entries.size()) + " id 寄存器=" + g.id_register);
  g.hook.set_process(GetCurrentProcess());
  win::InstallReport rep;
  if (!g.hook.install(GetCurrentProcess(), req, &rep)) {
    log_line("安装失败: " + rep.error);
    for (const auto& s : rep.steps) log_line("  步骤: " + s);
    return false;
  }
  for (const auto& s : rep.steps) log_line("  步骤: " + s);
  g.installed = true;
  log_line("安装成功：FileDataID hook 已生效（" + std::to_string(rep.entry_count) + " 条映射，" +
           std::to_string(rep.copy_len) + " 字节 detour）");
  return true;
}

// 把环形缓冲里新出现的记录转成文本写进日志（只在拦截模式用）。
void drain_intercept_log() {
  if (!g.intercepting || !g.intercept_ring.ok()) return;
  uint64_t counter = 0;
  if (!win::read_remote(GetCurrentProcess(),
                        reinterpret_cast<uint64_t>(g.intercept_counter.addr()), &counter, 8,
                        nullptr))
    return;
  if (counter == g.last_intercept_seq) return;
  const uint32_t ring_count = g.intercept_ring.size() / win::InterceptRecord::kSize;
  uint64_t from = std::max<uint64_t>(g.last_intercept_seq, counter > ring_count ? counter - ring_count : 0);
  std::string text;
  for (uint64_t seq = from + 1; seq <= counter; ++seq) {
    const uint64_t idx = (seq - 1) & (ring_count - 1);
    uint8_t rec[win::InterceptRecord::kSize];
    if (!win::read_remote(GetCurrentProcess(),
                          reinterpret_cast<uint64_t>(g.intercept_ring.addr()) +
                              idx * win::InterceptRecord::kSize,
                          rec, sizeof(rec), nullptr))
      continue;
    uint64_t rax, rcx, rdx, r8, r9, rsp, s;
    std::memcpy(&rax, rec + win::InterceptRecord::kRax, 8);
    std::memcpy(&rcx, rec + win::InterceptRecord::kRcx, 8);
    std::memcpy(&rdx, rec + win::InterceptRecord::kRdx, 8);
    std::memcpy(&r8, rec + win::InterceptRecord::kR8, 8);
    std::memcpy(&r9, rec + win::InterceptRecord::kR9, 8);
    std::memcpy(&rsp, rec + win::InterceptRecord::kRsp, 8);
    std::memcpy(&s, rec + win::InterceptRecord::kSeq, 8);
    text += "#" + std::to_string(s) + " rax=" + to_hex(rax, 16) + " rcx=" + to_hex(rcx, 16) +
            " rdx=" + to_hex(rdx, 16) + " r8=" + to_hex(r8, 16) + " r9=" + to_hex(r9, 16) +
            " rsp=" + to_hex(rsp, 16) + "\n";
  }
  g.last_intercept_seq = counter;
  if (!text.empty()) {
    HANDLE h = CreateFileW(utf8_to_wide(to_native_path(g.intercept_log)).c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
      DWORD w = 0;
      WriteFile(h, text.data(), static_cast<DWORD>(text.size()), &w, nullptr);
      CloseHandle(h);
    }
    log_line("拦截记录 " + std::to_string(counter - from) + " 条 -> " + g.intercept_log);
  }
}

// ---- 登录界面触发：等到输入焦点/主窗口出现后再安装，避免在初始化阶段打补丁 ----
bool login_screen_ready() {
  // 客户端登录界面一定会有可见的顶层窗口；这里用「有可见窗口且尺寸合理」作为判据，
  // 不依赖窗口标题（私服会改标题），也不依赖 Lua。
  struct Ctx { bool found; } ctx{false};
  EnumWindows(
      [](HWND hwnd, LPARAM lp) -> BOOL {
        auto* c = reinterpret_cast<Ctx*>(lp);
        if (!IsWindowVisible(hwnd)) return TRUE;
        RECT r;
        if (!GetClientRect(hwnd, &r)) return TRUE;
        if (r.right - r.left < 320 || r.bottom - r.top < 240) return TRUE;
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid != GetCurrentProcessId()) return TRUE;
        c->found = true;
        return FALSE;
      },
      reinterpret_cast<LPARAM>(&ctx));
  return ctx.found;
}

DWORD WINAPI watcher_thread(void*) {
  // 等游戏窗口出现
  for (int i = 0; i < 600 && !g.triggered; ++i) {
    if (login_screen_ready()) {
      g.triggered = true;
      log_line("检测到游戏窗口（登录界面），触发条件满足");
      if (g.mode == "auto" && g.auto_trigger) install_now("登录界面触发");
      break;
    }
    Sleep(500);
  }
  // 热键循环（RegisterHotKey 也可以，但它会影响其他程序的同一热键；这里用轮询）
  bool down = false;
  while (!g.self) Sleep(1000);  // DLL 卸载后自然结束
  return 0;
}

DWORD WINAPI hotkey_thread(void*) {
  if (g.hotkey == 0) return 0;
  bool was_down = false;
  for (;;) {
    const bool down = (GetAsyncKeyState(static_cast<int>(g.hotkey)) & 0x8000) != 0;
    if (down && !was_down) {
      was_down = true;
      if (!g.installed) {
        log_line("热键：请求安装 hook");
        install_now("热键");
      } else {
        log_line("热键：hook 已安装（再次按下不重复安装）");
      }
      drain_intercept_log();
    } else if (!down) {
      was_down = false;
    }
    if (g.intercepting) drain_intercept_log();
    Sleep(50);
  }
}

std::string game_dir_from_module(const std::string& module_path) {
  const std::string dir = parent_path(module_path);
  // 如果 exe 在 _retail_/_midnight_ 之类的子目录里，回到上一层
  const std::string base = to_lower(file_name(dir));
  if (base == "_retail_" || base == "_classic_" || base == "_classic_era_" ||
      base.find("midnight") != std::string::npos)
    return parent_path(dir);
  return dir;
}

bool init() {
  g.init_called = true;
  const std::string game_dir = game_dir_from_module(g.module_path);
  const std::string wowmod_dir = join_path(game_dir, "wowmod");
  g.log_path = env_str(L"WOWMOD_RT_LOG");
  if (g.log_path.empty()) g.log_path = join_path(wowmod_dir, "wowmod_rt.log");
  g.report_path = join_path(wowmod_dir, "wowmod-analysis.txt");
  g.intercept_log = join_path(wowmod_dir, "wowmod-intercept.log");

  log_line("=== wowmod_rt.dll 启动 ===");
  log_line("主模块: " + g.module_path);
  log_line("基址 0x" + to_hex(g.image_base, 16) + ", 映像大小 " +
           std::to_string(g.image_size / 1048576) + " MB");

  g.mode = to_lower(env_str(L"WOWMOD_RT_MODE"));
  // observe（默认，只分析）| auto（登录界面后自动拦截）| hook（直接打重定向补丁）
  if (g.mode != "auto" && g.mode != "hook") g.mode = "observe";
  g.id_register = env_str(L"WOWMOD_RT_IDREG");
  if (g.id_register.empty()) g.id_register = "rdx";
  g.return_register = env_str(L"WOWMOD_RT_RETREG");
  if (g.return_register.empty()) g.return_register = "rax";
  g.forced_hook_rva = env_hex(L"WOWMOD_RT_HOOK_RVA", 0);
  g.auto_trigger = env_hex(L"WOWMOD_RT_AUTOTRIGGER", 1) != 0;
  const uint64_t hk = env_hex(L"WOWMOD_RT_HOTKEY", VK_F8);
  g.hotkey = static_cast<UINT>(hk);

  g.files_dir = env_str(L"WOWMOD_RT_FILES");
  if (g.files_dir.empty()) g.files_dir = join_path(wowmod_dir, "files");

  log_line("模式: " + g.mode + ", id 寄存器: " + g.id_register + ", 热键: 0x" +
           to_hex(g.hotkey, 2) + ", files: " + g.files_dir);

  // 1) 映射表 + 本地文件
  MappingTable maps;
  load_mappings(game_dir, &maps);
  load_entries(g.files_dir, maps, &g.entries);

  // 2) 分析内存映像
  run_analysis();
  write_report();

  // 3) 观察模式到此为止
  if (g.mode != "auto" && g.forced_hook_rva == 0) {
    log_line("观察模式：未修改客户端任何字节。按 F8（或配置的热键）可手动安装。");
  }

  if (g.forced_hook_rva) {
    log_line("使用配置的固定 hook RVA 0x" + to_hex(g.forced_hook_rva, 1));
  }

  HANDLE w = CreateThread(nullptr, 0, watcher_thread, nullptr, 0, nullptr);
  if (w) CloseHandle(w);
  HANDLE h = CreateThread(nullptr, 0, hotkey_thread, nullptr, 0, nullptr);
  if (h) CloseHandle(h);
  return true;
}

// 供 rt_entry.cpp 调用（直接跳入执行时走这条路径，不依赖 DllMain）。
static DWORD WINAPI init_worker(void*);
}  // namespace

// 纯 Win32 的"我进来了"信号：故意不用 std::string / CRT 任何东西。
// 手工映射场景下 CRT 可能没初始化好，这一句必须绝对可靠 ——
// 它存在就证明代码真的在客户端进程里跑起来了。
static void early_beacon(const wchar_t* dir) {
  if (!dir || !*dir) return;
  std::wstring path(dir);
  if (!path.empty() && path.back() != L'\\') path.push_back(L'\\');
  path += L"wowmod_beacon.txt";
  HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return;
  char buf[160] = {0};
  const char* msg = "wowmod runtime alive in client process\r\n";
  size_t n = 0;
  while (msg[n] && n < sizeof(buf) - 1) { buf[n] = msg[n]; ++n; }
  DWORD w = 0;
  WriteFile(h, buf, static_cast<DWORD>(n), &w, nullptr);
  CloseHandle(h);
}

extern "C" int wowmod_rt_start(void* module_base) {
  using namespace wowmod;
  {

  if (g.started) return 1;
  g.started = true;
  {
    // 先落 beacon：即使后面全部失败，也能确认代码跑起来了
    wchar_t exe[MAX_PATH * 4] = {0};
    const DWORD n = GetModuleFileNameW(nullptr, exe, static_cast<DWORD>(std::size(exe)));
    if (n) {
      std::wstring dir(exe, n);
      const size_t slash = dir.find_last_of(L"\\/");
      if (slash != std::wstring::npos) {
        dir = dir.substr(0, slash + 1) + L"wowmod";
        CreateDirectoryW(dir.c_str(), nullptr);
        early_beacon(dir.c_str());
      }
    }
  }
  g.self = static_cast<HMODULE>(module_base);
  if (!main_module_info(&g.module_path, &g.image_base, &g.image_size)) return -1;
  HANDLE t = CreateThread(nullptr, 0, init_worker, nullptr, 0, nullptr);
  if (t) CloseHandle(t);
  return 0;
  }
}

namespace {

DWORD WINAPI init_worker(void*) {
  // 不依赖 SEH（zig/clang 交叉编译时 __try 不可用）。所有可能越界的读取都在
  // analyze/xref/detour 内部逐条校验过；这里做最后一层保护：
  // 读取映像范围时先 VirtualQuery，遇到不可读页直接跳过。
  init();
  return 0;
}

}  // namespace

#ifndef WOWMOD_EMBEDDED
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hModule);
    // 统一走 wowmod_rt_start：DllMain 与「直接跳入」两条路径行为一致。
    // 不在 DllMain 里做重活（loader lock），只起线程。
    wowmod_rt_start(hModule);
  }
  return TRUE;
}

#endif  // WOWMOD_EMBEDDED

extern "C" {

__declspec(dllexport) const char* WINAPI wowmod_rt_version() { return "wowmod_rt 2.0.0"; }

// 让嵌入 wowmod_rt.dll 的启动器在【不修改游戏 exe】的前提下也能拿到分析结果：
// 启动器把游戏以挂起状态创建 -> 进程里只有 Wow.exe 被映射（还没有原地解密/
// 影子加载），此时这里用 VirtualAllocEx 把 wowmod_rt.dll 手工映射进去并调用
// 本函数。分析结果写在 wowmod-analysis.txt/.json 里。
__declspec(dllexport) int WINAPI wowmod_rt_analyze_now() {
  if (!g.init_called) init();
  return g.analysis.ok ? 1 : 0;
}

__declspec(dllexport) int WINAPI wowmod_rt_installed() { return g.installed ? 1 : 0; }

__declspec(dllexport) int WINAPI wowmod_rt_install() {
  return install_now("外部调用") ? 1 : 0;
}

__declspec(dllexport) int WINAPI wowmod_rt_uninstall() {
  if (g.intercepting) {
    drain_intercept_log();
    win::remove_interceptors(GetCurrentProcess(), &g.intercept_detours, &g.intercept_stubs);
    g.intercepting = false;
    log_line("拦截已撤销");
    return 1;
  }
  if (!g.installed) return 1;
  const bool ok = g.hook.remove();
  g.installed = false;
  log_line(ok ? "hook 已卸载，原始指令已写回" : "hook 卸载失败");
  return ok ? 1 : 0;
}

// 让脚本/调试器可以取到报告路径
__declspec(dllexport) const char* WINAPI wowmod_rt_report_path() { return g.report_path.c_str(); }

}  // extern "C"
#endif
