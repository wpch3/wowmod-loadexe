// wowmod 应用主程序（窗口程序，无控制台）。
//
// 这是一个【应用】，不是一个测试台：
//   打开后就是一张表：左上是客户端，右上是 listfile，中间是模组目录；
//   下面一排大按钮：选择 / 下载 listfile / 扫描 / 启动游戏；
//   底部是实时日志和状态条。
//
// 为什么必须是窗口程序：
//   以前的形态是一堆 .cmd + .ps1 + .exe，每一步失败的方式都不一样
//   （路径带引号、python 没装、mappings 没生成、代理没生效...）。
//   用户要的是「一个完整的应用」，所以把全部步骤收进一个进程里，
//   任何一步失败都在界面上直接用中文说清楚，不留"看不出来但没生效"的状态。
//
// 关键设计：
//   * 不写控制台：SUBSYSTEM:WINDOWS。所有输出走 wowmod::logf -> 界面 + 日志文件。
//   * 启动游戏与安装补丁在【后台线程】做，界面不卡（扫描可能要几十秒）。
//   * 每一步的真实结果都写进日志文件，出问题能拿日志说话。
// SPDX-License-Identifier: MIT
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "wowmod/log.hpp"
#include "wowmod/mod_entry.hpp"
#include "wowmod/mods_selfcontained.hpp"
#include "wowmod/util.hpp"
#include "wowmod/version.hpp"
#include "windows/archive_extract.hpp"
#include "windows/listfile_fetch.hpp"
#include "windows/mod_loader.hpp"

#ifndef WOWMOD_APP_BUILD_TAG
#define WOWMOD_APP_BUILD_TAG "app-1"
#endif

namespace fs = std::filesystem;

namespace {

// ---- 控件 ID ----
enum : int {
  kIdExe = 1001,
  kIdExeBrowse,
  kIdMods,
  kIdModsBrowse,
  kIdList,
  kIdListBrowse,
  kIdListDownload,
  kIdScan,
  kIdUnpack,
  kIdLaunch,
  kIdLog,
  kIdStatus,
  kIdProgress,
  kIdCertCheck,
  kIdExeLabel,
  kIdModsLabel,
  kIdListLabel,
};

const wchar_t* kClass = L"WowmodAppWindow";
const wchar_t* kTitle = L"wowmod  —  WoW 12.0.7 模组加载器";

HWND g_exe = nullptr, g_mods = nullptr, g_list = nullptr;
HWND g_log = nullptr, g_status = nullptr, g_progress = nullptr;
HWND g_btn_scan = nullptr, g_btn_launch = nullptr, g_btn_dl = nullptr;
HWND g_btn_unpack = nullptr;
HWND g_cert = nullptr;
HFONT g_font_ui = nullptr, g_font_log = nullptr;

std::atomic<bool> g_busy{false};
std::atomic<bool> g_cancel{false};
std::mutex g_log_mu;
std::vector<std::string> g_pending;          // 后台线程 -> 界面线程的日志队列
std::string g_state_dir;                     // %LOCALAPPDATA%\wowmod

// ------------------------------------------------------------------ 工具

std::string wide_to_utf8(const std::wstring& w) {
  if (w.empty()) return "";
  const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0,
                                    nullptr, nullptr);
  std::string s(static_cast<size_t>(n < 0 ? 0 : n), '\0');
  if (n > 0)
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &s[0], n, nullptr,
                        nullptr);
  return s;
}

std::wstring utf8_to_wide_(const std::string& s) { return wowmod::utf8_to_wide(s); }

std::string control_text(HWND h) {
  const int n = GetWindowTextLengthW(h);
  if (n <= 0) return "";
  std::wstring buf(static_cast<size_t>(n) + 1, L'\0');
  GetWindowTextW(h, &buf[0], n + 1);
  buf.resize(static_cast<size_t>(n));
  return wide_to_utf8(buf);
}

void set_control_text(HWND h, const std::string& s) {
  SetWindowTextW(h, utf8_to_wide_(s).c_str());
}

// 跨线程改控件文本：只投递一个 heap 上的字符串，界面线程收到后释放。
// 注意不要在这里传栈地址 —— 消息是异步的，栈早就没了。
HWND g_main;
void set_control_text_async(HWND h, const std::string& s) {
  if (!g_main || !h) return;
  auto* p = new std::pair<HWND, std::string>(h, s);
  if (!PostMessageW(g_main, WM_APP + 3, 0, reinterpret_cast<LPARAM>(p))) delete p;
}

void apply_busy_ui(bool busy);   // 定义在「后台任务框架」一节，这里先声明

// 状态栏文字。可能从后台线程调用 —— 绝不直接碰控件，改成投递消息，
// 由界面线程在 WM_APP_STATUS 里真正写。直接跨线程 SetWindowText 会随机卡死。
std::atomic<bool> g_main_alive{false};
std::mutex g_status_mu;
std::string g_status_pending;

void set_status(const std::string& s) {
  {
    std::lock_guard<std::mutex> lk(g_status_mu);
    g_status_pending = s;
  }
  if (g_main_alive) PostMessageW(g_main, WM_APP + 1, 0, 0);
}

void apply_pending_status() {
  std::string s;
  {
    std::lock_guard<std::mutex> lk(g_status_mu);
    s.swap(g_status_pending);
  }
  if (!s.empty()) set_control_text(g_status, s);
}

// ------------------------------------------------------------------ 日志

// 后台线程调用：只排队，由界面线程追加到编辑框（跨线程操作控件风险很大）
void sink(const char* line, void*) {
  std::lock_guard<std::mutex> lk(g_log_mu);
  if (g_pending.size() < 20000) g_pending.emplace_back(line ? line : "");
}

void append_log_now(const std::string& text) {
  if (!g_log) return;
  // 只在末尾插入，不要 SelectAll —— 那会让编辑框持续闪烁并丢掉用户的选中
  const int len = GetWindowTextLengthW(g_log);
  SendMessageW(g_log, EM_SETSEL, static_cast<WPARAM>(len), static_cast<LPARAM>(len));
  const std::wstring w = utf8_to_wide_(text);
  SendMessageW(g_log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(w.c_str()));
  SendMessageW(g_log, EM_SCROLLCARET, 0, 0);
}

void drain_log() {
  std::vector<std::string> batch;
  {
    std::lock_guard<std::mutex> lk(g_log_mu);
    if (g_pending.empty()) return;
    batch.swap(g_pending);
  }
  std::string text;
  for (const auto& l : batch) {
    text += l;
    text += "\r\n";
  }
  append_log_now(text);
}

// ------------------------------------------------------------------ 状态持久化

std::string state_file() {
  return g_state_dir.empty() ? "" : wowmod::join_path(g_state_dir, "wowmod-app.ini");
}

void save_settings() {
  const std::string f = state_file();
  if (f.empty()) return;
  std::string body;
  body += "exe=" + control_text(g_exe) + "\n";
  body += "mods=" + control_text(g_mods) + "\n";
  body += "listfile=" + control_text(g_list) + "\n";
  body += std::string("cert=") + ((SendMessageW(g_cert, BM_GETCHECK, 0, 0) == BST_CHECKED) ? "1" : "0") +
          "\n";
  std::string err;
  wowmod::write_text_file(f, body, &err);
}

void load_settings() {
  const std::string f = state_file();
  if (f.empty()) return;
  std::string body, err;
  if (!wowmod::read_text_file(f, &body, &err)) return;
  size_t pos = 0;
  while (pos < body.size()) {
    size_t nl = body.find('\n', pos);
    const std::string line =
        body.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
    pos = nl == std::string::npos ? body.size() : nl + 1;
    const size_t eq = line.find('=');
    if (eq == std::string::npos) continue;
    const std::string k = line.substr(0, eq);
    const std::string v = line.substr(eq + 1);
    if (k == "exe") set_control_text(g_exe, v);
    else if (k == "mods") set_control_text(g_mods, v);
    else if (k == "listfile") set_control_text(g_list, v);
    else if (k == "cert") SendMessageW(g_cert, BM_SETCHECK, v == "1" ? BST_CHECKED : BST_UNCHECKED, 0);
  }
}

// ------------------------------------------------------------------ 选择对话框

// 统一的文件/目录选择器。返回空串表示用户取消。
std::string pick_path(HWND owner, bool directory, const wchar_t* filter,
                      const wchar_t* title) {
  std::vector<wchar_t> buf(32768, L'\0');
  if (directory) {
    BROWSEINFOW bi;
    ZeroMemory(&bi, sizeof(bi));
    bi.hwndOwner = owner;
    bi.lpszTitle = title;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_USENEWUI;
    LPITEMIDLIST idl = SHBrowseForFolderW(&bi);
    if (!idl) return "";
    const bool ok = SHGetPathFromIDListW(idl, buf.data()) != FALSE;
    CoTaskMemFree(idl);
    return ok ? wide_to_utf8(buf.data()) : "";
  }
  OPENFILENAMEW ofn;
  ZeroMemory(&ofn, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = owner;
  ofn.lpstrFilter = filter;
  ofn.lpstrFile = buf.data();
  ofn.nMaxFile = static_cast<DWORD>(buf.size());
  ofn.lpstrTitle = title;
  ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER;
  if (!GetOpenFileNameW(&ofn)) return "";
  return wide_to_utf8(buf.data());
}

// ------------------------------------------------------------------ 自动发现

// 找客户端：先看用户给过的目录，再扫常见安装位置。
// 只认真正的客户端 exe（大小 > 50 MB 且文件名像 Wow / 包含 Firestorm），
// 避免把 launcher / 修复工具当客户端。
std::string guess_client_exe(const std::string& hint_dir) {
  std::vector<fs::path> roots;
  if (!hint_dir.empty()) roots.push_back(fs::u8path(hint_dir));
  const char* envs[] = {"ProgramFiles", "ProgramFiles(x86)"};
  for (const char* e : envs) {
    const char* v = std::getenv(e);
    if (!v) continue;
    for (const char* sub : {"\\World of Warcraft", "\\World of Warcraft\\_retail_",
                            "\\World of Warcraft\\_midnight_", "\\Midnight Open Beta"})
      roots.push_back(fs::u8path(std::string(v) + sub));
  }
  for (const char* drive : {"C:", "D:", "E:", "F:"}) {
    for (const char* sub : {"\\Midnight Open Beta", "\\World of Warcraft", "\\Games\\World of Warcraft"})
      roots.push_back(fs::u8path(std::string(drive) + sub));
  }

  std::error_code ec;
  for (const auto& r : roots) {
    if (!fs::is_directory(r, ec)) continue;
    for (const auto& ent : fs::directory_iterator(r, fs::directory_options::skip_permission_denied,
                                                 ec)) {
      if (ec) break;
      if (!ent.is_regular_file(ec)) continue;
      const std::string name = ent.path().filename().u8string();
      std::string low = name;
      for (auto& c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      if (low.size() < 4 || low.compare(low.size() - 4, 4, ".exe") != 0) continue;
      if (low.find("wow") == std::string::npos && low.find("firestorm") == std::string::npos)
        continue;
      if (low.find("launcher") != std::string::npos) continue;
      if (fs::file_size(ent.path(), ec) < (50ull << 20)) continue;
      return ent.path().u8string();
    }
  }
  return "";
}

// ------------------------------------------------------------------ 扫描（后台线程）

struct ScanOutcome {
  bool ok = false;
  size_t matched = 0;
  std::string error;
  std::string summary;
};

// 把扫描结果写成 <state>\scan.txt，供"启动游戏"复用，避免每次重扫 147 MB 表。
void write_scan_cache(const std::string& mods, const std::string& listfile,
                      const wowmod::win::SelfContainedReport& rep);

ScanOutcome run_scan(const std::string& mods, const std::string& listfile,
                     std::function<void(int)> on_percent) {
  ScanOutcome out;
  using namespace wowmod::win;

  on_percent(5);
  wowmod::logf("=== 开始扫描 ===");
  wowmod::logf("模组目录: %s", mods.c_str());
  wowmod::logf("listfile: %s", listfile.c_str());

  std::error_code ec;
  if (!fs::is_directory(fs::u8path(mods), ec)) {
    out.error = "模组目录不存在或不可访问";
    return out;
  }
  if (!fs::is_regular_file(fs::u8path(listfile), ec)) {
    out.error = "listfile 不存在（请先下载）";
    return out;
  }

  on_percent(10);
  // 单个 CSV 就是全部；split_listfiles 支持 ';' 分隔的多个文件。
  const auto sc = build_selfcontained_mods(mods, split_listfiles(listfile));
  on_percent(90);

  wowmod::logf("扫到文件 %zu 个", sc.files_scanned);
  wowmod::logf("解析出 FileDataID %zu 个（精确 %zu / _HD %zu / 文件名 %zu）", sc.matched,
               sc.by_exact, sc.by_hd, sc.by_name);
  if (sc.ambiguous) wowmod::logf("重名无法确定 %zu 个（已拒绝，绝不猜）", sc.ambiguous);
  if (sc.duplicates) wowmod::logf("同一 id 重复 %zu 个（保留第一个，与 Arctium 一致）", sc.duplicates);
  if (sc.missing) wowmod::logf("未解析 %zu 个（下面最多列 15 条）", sc.missing);
  for (size_t i = 0; i < sc.unresolved.size() && i < 15; ++i)
    wowmod::logf("    %s", sc.unresolved[i].c_str());

  if (!sc.ok) {
    out.error = sc.error.empty() ? "一个 FileDataID 都没解析出来" : sc.error;
    return out;
  }

  write_scan_cache(mods, listfile, sc);
  on_percent(100);

  out.ok = true;
  out.matched = sc.matched;
  out.summary = std::to_string(sc.matched) + " 个文件可用";
  wowmod::logf("=== 扫描完成: %s ===", out.summary.c_str());
  return out;
}

void write_scan_cache(const std::string& mods, const std::string& listfile,
                      const wowmod::win::SelfContainedReport& rep) {
  const std::string f = wowmod::join_path(g_state_dir, "scan.txt");
  std::string body;
  body += mods + "\n";
  body += listfile + "\n";
  for (const auto& e : rep.entries) {
    body += std::to_string(e.file_data_id);
    body += ';';
    body += e.local_path;
    body += ';';
    body += e.game_path;
    body += '\n';
  }
  std::string err;
  wowmod::write_text_file(f, body, &err);
}

// ------------------------------------------------------------------ 后台任务框架

// 这两件事都涉及控件，必须只在界面线程做。
// set_busy_ui 可能从后台线程（end_job）调用，所以它只投递消息。
void apply_busy_ui(bool busy) {
  EnableWindow(g_btn_scan, !busy);
  EnableWindow(g_btn_launch, !busy);
  EnableWindow(g_btn_dl, !busy);
  EnableWindow(g_btn_unpack, !busy);
  if (busy && g_progress) PostMessageW(g_progress, PBM_SETPOS, 0, 0);
}

void set_busy_ui(bool busy) {
  if (g_main_alive) PostMessageW(g_main, WM_APP + 2, busy ? 1 : 0, 0);
}

struct Job {
  std::function<void()> fn;
};

DWORD WINAPI job_thread(LPVOID p) {
  Job* j = static_cast<Job*>(p);
  j->fn();
  delete j;
  return 0;
}

void start_job(std::function<void()> fn) {
  if (g_busy.exchange(true)) return;
  set_busy_ui(true);
  Job* j = new Job{std::move(fn)};
  HANDLE h = CreateThread(nullptr, 0, job_thread, j, 0, nullptr);
  if (h) CloseHandle(h);
}

void end_job() {
  g_busy = false;
  set_busy_ui(false);
}

// ------------------------------------------------------------------ 各按钮动作

void do_scan() {
  const std::string mods = control_text(g_mods);
  const std::string lf = control_text(g_list);
  if (mods.empty()) {
    MessageBoxW(nullptr, L"请先选择模组目录。", L"wowmod", MB_ICONINFORMATION);
    return;
  }
  if (lf.empty()) {
    MessageBoxW(nullptr, L"还没有 listfile。请先点「下载 listfile」。", L"wowmod",
                MB_ICONINFORMATION);
    return;
  }
  save_settings();
  start_job([mods, lf]() {
    auto outcome = run_scan(mods, lf, [](int pct) {
      if (g_progress) PostMessageW(g_progress, PBM_SETPOS, static_cast<WPARAM>(pct), 0);
    });
    if (outcome.ok) {
      set_status("扫描完成：" + outcome.summary + "。点「启动游戏」开始。");
    } else {
      wowmod::logf("[失败] %s", outcome.error.c_str());
      set_status("扫描失败：" + outcome.error);
    }
    end_job();
  });
}

void do_download() {
  const std::string out = wowmod::join_path(g_state_dir, "wow-listfile.csv");
  start_job([out]() {
    wowmod::logf("=== 开始下载 listfile（约 150 MB，只需一次）===");
    set_status("正在下载 listfile ...");
    auto res = wowmod::win::fetch_listfile(out, [](const wowmod::win::FetchProgress& p) {
      if (p.total && g_progress) {
        const int pct = static_cast<int>((p.done * 100) / p.total);
        PostMessageW(g_progress, PBM_SETPOS, static_cast<WPARAM>(pct), 0);
      }
      if (g_status && p.total)
        set_status(p.stage + "：" + std::to_string(p.done / (1024 * 1024)) + " / " +
                   std::to_string(p.total / (1024 * 1024)) + " MB");
    });
    if (res.ok) {
      wowmod::logf("下载完成: %s（%llu 字节）", res.path.c_str(),
                   static_cast<unsigned long long>(res.bytes));
      set_control_text_async(g_list, res.path);
      save_settings();
      if (g_progress) PostMessageW(g_progress, PBM_SETPOS, 100, 0);
      set_status("listfile 已就绪。现在点「扫描模组」。");
    } else {
      wowmod::logf("[失败] %s", res.error.c_str());
      set_status("下载失败：" + res.error);
    }
    end_job();
  });
}

// 解压用户丢进来的模组包。
//
// 为什么不要求用户自己解压：
//   真实模组包长这样 —— T21WarriorNSFW.rar / Titaa Hawkstrider Mount.7z。
//   用户解压后的目录层级完全不可控，而"解到哪一层"直接决定
//   Character\ 这种前缀能不能对上。所以由程序固定解到 state\mods\<包名>\，
//   再让扫描器自己按第一个游戏前缀目录去裁剪路径 —— 无论包里有几层。
void do_unpack() {
  const std::string archive = pick_path(g_main, false,
                                        L"模组压缩包 (*.zip;*.rar;*.7z)\0*.zip;*.rar;*.7z\0"
                                        L"所有文件\0*.*\0",
                                        L"选择模组压缩包（也可以直接把包拖进窗口）");
  if (archive.empty()) return;

  const std::string stem = wowmod::win::archive_stem(archive);
  const std::string out = wowmod::join_path(wowmod::join_path(g_state_dir, "mods"), stem);
  const std::string lf0 = control_text(g_list);   // 界面线程先读

  start_job([archive, out, stem, lf0]() {
    using namespace wowmod::win;
    wowmod::logf("=== 解压 %s ===", archive.c_str());
    set_status("正在解压 ...");
    std::error_code ec;
    fs::remove_all(fs::u8path(out), ec);
    auto r = extract_archive(archive, out, [](const std::string& line) { wowmod::logf("  %s", line.c_str()); });
    if (!r.ok) {
      wowmod::logf("[失败] %s", r.error.c_str());
      set_status("解压失败：" + r.error);
      end_job();
      return;
    }
    wowmod::logf("解压完成: %zu 个文件（工具 %s）-> %s", r.files, r.tool.c_str(), r.out_dir.c_str());
    set_control_text_async(g_mods, r.out_dir);
    save_settings();
    // 解压完直接接着扫描 —— 用户点了"解压"就是想用这个包
    set_status("解压完成（" + std::to_string(r.files) + " 个文件）。正在扫描 ...");
    const std::string lf = lf0;
    if (lf.empty()) {
      set_status("解压完成，已选为模组目录。还需要「下载 listfile」。");
      end_job();
      return;
    }
    auto outcome = run_scan(r.out_dir, lf, [](int pct) {
      if (g_progress) PostMessageW(g_progress, PBM_SETPOS, static_cast<WPARAM>(pct), 0);
    });
    if (outcome.ok)
      set_status("就绪：" + outcome.summary + "。点「启动游戏并加载」。");
    else
      set_status("扫描失败：" + outcome.error);
    end_job();
  });
}

// 拖放进来一个路径，按扩展名决定放哪儿：
//   压缩包 -> 解压并扫描（用户拖的意图就是这个）
//   目录   -> 当模组目录
//   .exe   -> 当客户端
//   .csv   -> 当 listfile
void on_dropped_path(const std::string& path) {
  std::error_code ec;
  if (fs::is_directory(fs::u8path(path), ec)) {
    set_control_text(g_mods, path);
    save_settings();
    wowmod::logf("拖入目录，已设为模组目录: %s", path.c_str());
    set_status("已选择模组目录。点「扫描模组」。");
    return;
  }
  std::string low = path;
  for (auto& c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  auto ends = [&](const char* suf) {
    const size_t n = std::strlen(suf);
    return low.size() > n && low.compare(low.size() - n, n, suf) == 0;
  };
  if (ends(".zip") || ends(".rar") || ends(".7z")) {
    const std::string stem = wowmod::win::archive_stem(path);
    const std::string out = wowmod::join_path(wowmod::join_path(g_state_dir, "mods"), stem);
    const std::string lf0 = control_text(g_list);
    start_job([path, out, lf0]() {
      using namespace wowmod::win;
      wowmod::logf("=== 解压（拖入）%s ===", path.c_str());
      set_status("正在解压 ...");
      std::error_code e2;
      fs::remove_all(fs::u8path(out), e2);
      auto r = extract_archive(path, out,
                               [](const std::string& l) { wowmod::logf("  %s", l.c_str()); });
      if (!r.ok) {
        wowmod::logf("[失败] %s", r.error.c_str());
        set_status("解压失败：" + r.error);
        end_job();
        return;
      }
      wowmod::logf("解压完成: %zu 个文件 -> %s", r.files, r.out_dir.c_str());
      // 跨线程：只投递，不直接写控件
      set_control_text_async(g_mods, r.out_dir);
      save_settings();
      const std::string lf = lf0;
      if (lf.empty()) {
        set_status("解压完成，已选为模组目录。还需要「下载 listfile」。");
        end_job();
        return;
      }
      auto outcome = run_scan(r.out_dir, lf, [](int pct) {
        if (g_progress) PostMessageW(g_progress, PBM_SETPOS, static_cast<WPARAM>(pct), 0);
      });
      set_status(outcome.ok ? ("就绪：" + outcome.summary + "。点「启动游戏并加载」。")
                            : ("扫描失败：" + outcome.error));
      end_job();
    });
    return;
  }
  if (ends(".exe")) {
    set_control_text(g_exe, path);
    if (control_text(g_mods).empty()) set_control_text(g_mods, wowmod::parent_path(path));
    save_settings();
    wowmod::logf("拖入 exe，已设为客户端: %s", path.c_str());
    set_status("已选择客户端。");
    return;
  }
  if (ends(".csv")) {
    set_control_text(g_list, path);
    save_settings();
    wowmod::logf("拖入 csv，已设为 listfile: %s", path.c_str());
    set_status("已选择 listfile。点「扫描模组」。");
    return;
  }
  set_status("不认识的文件类型，可以拖：压缩包 / 模组目录 / 客户端 exe / listfile.csv");
}

void do_launch() {
  const std::string exe = control_text(g_exe);
  const std::string mods = control_text(g_mods);
  const std::string lf = control_text(g_list);
  if (exe.empty()) {
    MessageBoxW(nullptr, L"请先选择客户端 exe。", L"wowmod", MB_ICONINFORMATION);
    return;
  }
  if (mods.empty() || lf.empty()) {
    MessageBoxW(nullptr, L"请先选择模组目录并准备好 listfile。", L"wowmod", MB_ICONINFORMATION);
    return;
  }
  save_settings();
  // 【跨线程规则】控件只能在界面线程读写。这里先把勾选状态读出来，
  // 传值给后台线程 —— 之前是在后台线程里直接 SendMessageW(g_cert)，
  // 那是跨线程同步调用窗口过程，安装进行到一半时窗口若被销毁，
  // 线程会永久阻塞（SendMessage 不会超时）。
  const bool want_cert = (SendMessageW(g_cert, BM_GETCHECK, 0, 0) == BST_CHECKED);
  start_job([exe, mods, lf, want_cert]() {
    using namespace wowmod::win;

    // 数据侧先算好（在启动客户端之前），这样"启动 → 等待 → 安装"不会
    // 因为读 147 MB 的表而多等一份时间。
    wowmod::logf("=== 准备安装 ===");
    set_status("正在解析模组 ...");
    const auto sc = build_selfcontained_mods(mods, split_listfiles(lf));
    if (!sc.ok) {
      wowmod::logf("[失败] %s", sc.error.c_str());
      set_status("失败：" + sc.error);
      end_job();
      return;
    }
    wowmod::logf("解析完成: %zu 项（精确 %zu / _HD %zu / 文件名 %zu）", sc.matched, sc.by_exact,
                 sc.by_hd, sc.by_name);

    ModDataSet ds;
    ds.entries = sc.entries;
    ds.files_dir = sc.game_root;
    ds.source_note = "应用内扫描（" + std::to_string(sc.matched) + " 项）";

    // 启动客户端（挂起 → 恢复主线程），再装。
    // 这里直接复用引擎，不经过 CLI：少一层解析，少一类失败。
    set_status("正在启动客户端 ...");
    wowmod::logf("启动: %s", exe.c_str());

    std::wstring cmd = L"\"" + utf8_to_wide_(exe) + L"\"";
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(L'\0');
    const std::wstring wd = utf8_to_wide_(wowmod::parent_path(exe));
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr,
                        wd.c_str(), &si, &pi)) {
      const std::string e = "启动客户端失败 (GetLastError=" + std::to_string(GetLastError()) + ")";
      wowmod::logf("[失败] %s", e.c_str());
      set_status(e);
      end_job();
      return;
    }
    wowmod::logf("客户端已创建 PID %lu（挂起）", pi.dwProcessId);
    ResumeThread(pi.hThread);
    ::Sleep(400);   // 让 ntdll 加载器跑完，模块表才可用

    const std::string workdir = wowmod::parent_path(exe);
    const std::string wowmod_dir = wowmod::join_path(workdir, "wowmod");
    CreateDirectoryW(utf8_to_wide_(wowmod_dir).c_str(), nullptr);

    set_status("正在安装（anti-crash → NoJump → FileDataID 跳板）...");
    wowmod::logf("=== 安装开始 ===");
    ModLoaderOptions mopts;
    mopts.cert_patches = want_cert;
    if (mopts.cert_patches)
      wowmod::logf("已启用证书补丁（CertBundle / CertCommonName / CertChain / CertCheck）");
    ModLoaderResult r = install_mod_loader_with_data(pi.hProcess, wowmod_dir, ds, 120000,
                                                     StubKind::kArctium, mopts);
    const std::string text = format_mod_loader_report(r);
    wowmod::logf("%s", text.c_str());

    std::string werr;
    wowmod::write_text_file(wowmod::join_path(wowmod_dir, "wowmod-mods.txt"), text, &werr);
    if (GetFileAttributesW(utf8_to_wide_(wowmod::join_path(wowmod_dir, "wowmod-mods.txt")).c_str()) !=
        INVALID_FILE_ATTRIBUTES)
      wowmod::logf("报告: %s", wowmod::join_path(wowmod_dir, "wowmod-mods.txt").c_str());

    if (!r.ok) {
      wowmod::logf("[失败] %s", r.error.c_str());
      wowmod::logf("本次没有在客户端留下可用的模组加载器。");
      set_status("安装失败：" + r.error);
      // 【绝不能 TerminateProcess】
      //
      // 之前这里杀进程，用户看到的现象就是「游戏刚起来就闪退」——
      // 他会以为加载器把客户端弄崩了，而实际上是我们自己把它杀掉的。
      // 而且失败的安装本来就没写入任何东西，客户端是干净的，
      // 让它继续跑，用户可以直接在游戏里试、也可以关掉重来。
      wowmod::logf("客户端保持运行（本次没有改动它的任何字节）。"
                   "你可以直接进游戏，或关掉它重试。");
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      end_job();
      return;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    wowmod::logf("=== 安装成功。现在可以进游戏了（模组已在内存里生效）===");
    set_status("安装成功。客户端已启动，进游戏即可。关闭客户端后一切自动还原。");
    if (g_progress) PostMessageW(g_progress, PBM_SETPOS, 100, 0);
    end_job();
  });
}

// ------------------------------------------------------------------ 界面

const int kPad = 14;
const int kRowH = 26;
const int kLabelW = 92;
const int kPickW = 132;

// 标签只创建一次。以前在 layout() 里创建 —— WM_SIZE 每来一次就多一组
// 标签叠在窗口上，拖动边框立刻就能看出来。
void create_labels(HWND hwnd) {
  static const wchar_t* kTexts[3] = {L"客户端 exe", L"模组目录", L"listfile"};
  for (int i = 0; i < 3; ++i) {
    HWND h = CreateWindowExW(0, L"STATIC", kTexts[i], WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 10,
                             10, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdExeLabel + i)),
                             nullptr, nullptr);
    SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_ui), TRUE);
  }
}

void layout(HWND hwnd) {
  RECT rc;
  GetClientRect(hwnd, &rc);
  const int W = rc.right - rc.left;
  const int right_edge = kPad + kLabelW + (W - kPad * 2 - kLabelW - kPickW - 8) + 8 + kPickW;

  int y = kPad;
  HWND edits[3] = {g_exe, g_mods, g_list};
  for (int i = 0; i < 3; ++i) {
    HWND label = GetDlgItem(hwnd, kIdExeLabel + i);
    if (label) SetWindowPos(label, nullptr, kPad, y + 4, kLabelW, 20, SWP_NOZORDER);
    if (edits[i])
      SetWindowPos(edits[i], nullptr, kPad + kLabelW, y, W - kPad * 2 - kLabelW - kPickW - 8,
                   kRowH, SWP_NOZORDER);
    HWND pick = GetDlgItem(hwnd, kIdExeBrowse + i);
    if (pick)
      SetWindowPos(pick, nullptr, right_edge - kPickW, y, kPickW, kRowH, SWP_NOZORDER);
    y += kRowH + 8;
  }
  y += 8;

  // 按钮行
  const int bw = 150, bh = 40, gap = 10;
  int x = kPad;
  if (g_btn_dl) { SetWindowPos(g_btn_dl, nullptr, x, y, bw, bh, SWP_NOZORDER); x += bw + gap; }
  if (g_btn_unpack) { SetWindowPos(g_btn_unpack, nullptr, x, y, bw, bh, SWP_NOZORDER); x += bw + gap; }
  if (g_btn_scan) { SetWindowPos(g_btn_scan, nullptr, x, y, bw, bh, SWP_NOZORDER); x += bw + gap; }
  if (g_btn_launch) { SetWindowPos(g_btn_launch, nullptr, x, y, bw + 40, bh, SWP_NOZORDER); }
  y += bh + 12;

  if (g_cert) {
    SetWindowPos(g_cert, nullptr, kPad, y, W - kPad * 2, 22, SWP_NOZORDER);
    y += 22 + 6;
  }
  if (g_progress) SetWindowPos(g_progress, nullptr, kPad, y, W - kPad * 2, 18, SWP_NOZORDER);
  y += 18 + 8;
  if (g_status) SetWindowPos(g_status, nullptr, kPad, y, W - kPad * 2, 20, SWP_NOZORDER);
  y += 20 + 10;

  const int log_h = rc.bottom - y - kPad;
  if (g_log) SetWindowPos(g_log, nullptr, kPad, y, W - kPad * 2, log_h > 80 ? log_h : 80,
                          SWP_NOZORDER);
}

HWND mk_edit(HWND parent, int id, bool read_only) {
  HWND h = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                           WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL |
                               (read_only ? (ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL)
                                          : 0),
                           0, 0, 10, 10, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                           nullptr, nullptr);
  SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(read_only ? g_font_log : g_font_ui), TRUE);
  return h;
}

HWND mk_button(HWND parent, int id, const wchar_t* text) {
  HWND h = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                           0, 0, 10, 10, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                           nullptr, nullptr);
  SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_ui), TRUE);
  return h;
}

LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE: {
      g_exe = mk_edit(hwnd, kIdExe, false);
      g_mods = mk_edit(hwnd, kIdMods, false);
      g_list = mk_edit(hwnd, kIdList, false);

      mk_button(hwnd, kIdExeBrowse, L"选择客户端…");
      mk_button(hwnd, kIdModsBrowse, L"选择模组目录…");
      mk_button(hwnd, kIdListBrowse, L"选择 listfile…");

      g_btn_dl = mk_button(hwnd, kIdListDownload, L"下载 listfile");
      g_btn_unpack = mk_button(hwnd, kIdUnpack, L"解压模组包…");
      g_btn_scan = mk_button(hwnd, kIdScan, L"扫描模组");
      g_btn_launch = mk_button(hwnd, kIdLaunch, L"▶  启动游戏并加载");

      g_progress = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10,
                                   hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdProgress)),
                                   nullptr, nullptr);
      SendMessageW(g_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

      // 「私有服务器」模式：同时打 Arctium 的四个证书补丁。
      // 默认不开 —— 它对模组加载没有任何作用，只在客户端需要接受
      // 私有服务器证书时才需要（客户端不校验对方证书）。
      g_cert = CreateWindowExW(0, L"BUTTON", L"同时打证书补丁（连私有服务器时用）",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 0, 0, 10, 10,
                               hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCertCheck)),
                               nullptr, nullptr);
      SendMessageW(g_cert, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_ui), TRUE);

      g_status = CreateWindowExW(0, L"STATIC", L"就绪：选择客户端、模组目录，然后点「下载 listfile」。",
                                 WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, hwnd,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdStatus)), nullptr,
                                 nullptr);
      SendMessageW(g_status, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_ui), TRUE);

      g_log = mk_edit(hwnd, kIdLog, true);

      load_settings();
      if (control_text(g_exe).empty()) {
        const std::string guess = guess_client_exe("");
        if (!guess.empty()) {
          set_control_text(g_exe, guess);
          set_control_text(g_mods, wowmod::parent_path(guess));
        }
      }
      if (control_text(g_list).empty()) {
        const std::string lf = wowmod::join_path(g_state_dir, "wow-listfile.csv");
        std::error_code ec;
        if (fs::is_regular_file(fs::u8path(lf), ec)) set_control_text(g_list, lf);
      }
      create_labels(hwnd);
      layout(hwnd);
      wowmod::logf("wowmod 应用已启动（%s）", WOWMOD_APP_BUILD_TAG);
      wowmod::logf("状态目录: %s", g_state_dir.c_str());
      wowmod::logf("用法：1) 选客户端  2) 选模组目录  3) 下载 listfile（只需一次）  4) 扫描  5) 启动游戏");
      return 0;
    }

    case WM_SIZE:
      layout(hwnd);
      return 0;

    case WM_DROPFILES: {
      HDROP drop = reinterpret_cast<HDROP>(wp);
      const UINT n = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
      if (n > 0 && !g_busy) {
        std::vector<wchar_t> buf(32768, L'\0');
        if (DragQueryFileW(drop, 0, buf.data(), static_cast<UINT>(buf.size()))) {
          on_dropped_path(wide_to_utf8(buf.data()));
        }
      }
      DragFinish(drop);
      return 0;
    }

    case WM_APP + 1:
      apply_pending_status();
      return 0;

    case WM_APP + 2:
      apply_busy_ui(wp != 0);
      return 0;

    case WM_APP + 3: {   // 后台线程请求改某个控件文本
      std::unique_ptr<std::pair<HWND, std::string>> p(
          reinterpret_cast<std::pair<HWND, std::string>*>(lp));
      if (p && p->first) SetWindowTextW(p->first, utf8_to_wide_(p->second).c_str());
      return 0;
    }

    case WM_TIMER:
      if (wp == 1) {
        drain_log();
        apply_pending_status();
        return 0;
      }
      break;

    case WM_COMMAND: {
      const int id = LOWORD(wp);
      switch (id) {
        case kIdExeBrowse: {
          const std::string p = pick_path(hwnd, false, L"客户端 exe\0*.exe\0所有文件\0*.*\0",
                                          L"选择 Wow.exe / WoW 12.0.7 - Firestorm.exe");
          if (!p.empty()) {
            set_control_text(g_exe, p);
            if (control_text(g_mods).empty()) set_control_text(g_mods, wowmod::parent_path(p));
            save_settings();
          }
          return 0;
        }
        case kIdModsBrowse: {
          const std::string p = pick_path(hwnd, true, nullptr,
                                          L"选择模组目录（含 Character\\ 或 Creature\\ 的那一层）");
          if (!p.empty()) {
            set_control_text(g_mods, p);
            save_settings();
          }
          return 0;
        }
        case kIdListBrowse: {
          const std::string p = pick_path(hwnd, false, L"listfile (*.csv)\0*.csv\0所有文件\0*.*\0",
                                          L"选择 listfile（listfile.csv / wow-listfile.csv）");
          if (!p.empty()) {
            set_control_text(g_list, p);
            save_settings();
          }
          return 0;
        }
        case kIdListDownload:
          do_download();
          return 0;
        case kIdUnpack:
          do_unpack();
          return 0;
        case kIdScan:
          do_scan();
          return 0;
        case kIdLaunch:
          do_launch();
          return 0;
        default:
          break;
      }
      break;
    }

    case WM_CLOSE: {
      if (g_busy) {
        const int r = MessageBoxW(hwnd,
                                  L"还有任务正在跑（扫描或安装）。\n\n"
                                  L"现在关闭会中断安装；如果已经改到一半，客户端可能停在"
                                  L"装了跳板但没打补丁的状态（关掉游戏就恢复，不会损坏文件）。\n\n"
                                  L"仍然关闭吗？",
                                  L"wowmod", MB_ICONWARNING | MB_YESNO);
        if (r != IDYES) return 0;
      }
      save_settings();
      // 先让后台线程停止投递，再等它把任务做完（最多 3 秒）。
      // 不等的话，任务线程可能还在用 g_log / g_progress 这些已经销毁的
      // 控件句柄 —— 那会是一退出就崩，而且崩在 libc 里，很难查。
      g_main_alive = false;
      for (int i = 0; i < 30 && g_busy; ++i) ::Sleep(100);
      DestroyWindow(hwnd);
      return 0;
    }

    case WM_DESTROY:
      g_main_alive = false;
      KillTimer(hwnd, 1);
      if (g_font_ui) DeleteObject(g_font_ui);
      if (g_font_log) DeleteObject(g_font_log);
      PostQuitMessage(0);
      return 0;
    default:
      break;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show);

int main() {
  return wWinMain(GetModuleHandleW(nullptr), nullptr, nullptr, SW_SHOWDEFAULT);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show) {
  // 中文界面必须有清单启用 UTF-8/线程区域设置，否则编辑框里会出现问号。
  SetThreadUILanguage(0);
  CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

  INITCOMMONCONTROLSEX icc;
  icc.dwSize = sizeof(icc);
  icc.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
  InitCommonControlsEx(&icc);

  // 状态目录：%LOCALAPPDATA%\wowmod
  {
    wchar_t* p = nullptr;
    std::string base;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &p)) && p) {
      base = wide_to_utf8(p);
      CoTaskMemFree(p);
    }
    if (base.empty()) base = ".";
    g_state_dir = wowmod::join_path(base, "wowmod");
    std::error_code ec;
    fs::create_directories(fs::u8path(g_state_dir), ec);
  }

  // 日志同时落盘：出问题让用户直接把文件发过来
  wowmod::set_log_file(wowmod::join_path(g_state_dir, "wowmod-app.log"));
  wowmod::set_log_sink(sink, nullptr);

  // 字体：用系统 UI 字体，不要写死 "Microsoft YaHei"（某些精简系统没有）
  {
    NONCLIENTMETRICSW ncm;
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
      g_font_ui = CreateFontIndirectW(&ncm.lfMessageFont);
    if (!g_font_ui) g_font_ui = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    LOGFONTW lf;
    GetObjectW(g_font_ui, sizeof(lf), &lf);
    lf.lfHeight = -13;
    wcscpy(lf.lfFaceName, L"Consolas");
    g_font_log = CreateFontIndirectW(&lf);
    if (!g_font_log) g_font_log = g_font_ui;
  }

  WNDCLASSEXW wc;
  ZeroMemory(&wc, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = wnd_proc;
  wc.hInstance = inst;
  wc.lpszClassName = kClass;
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
  wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
  if (!RegisterClassExW(&wc)) return 1;

  const int w = 900, h = 720;
  // WS_EX_ACCEPTFILES = 接受拖放
  HWND hwnd = CreateWindowExW(WS_EX_ACCEPTFILES, kClass, kTitle,
                              WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                              CW_USEDEFAULT, CW_USEDEFAULT, w, h, nullptr, nullptr, inst, nullptr);
  if (!hwnd) return 1;
  g_main = hwnd;
  g_main_alive = true;
  ShowWindow(hwnd, show ? show : SW_SHOW);
  UpdateWindow(hwnd);

  SetTimer(hwnd, 1, 120, nullptr);   // 日志刷新节拍

  MSG msg;
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    if (!IsDialogMessageW(hwnd, &msg)) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
  }
  CoUninitialize();
  return 0;
}
