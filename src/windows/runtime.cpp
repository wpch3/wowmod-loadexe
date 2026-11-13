// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/runtime.hpp"

#include <windows.h>

#include <algorithm>
#include <cstdlib>
#include <mutex>

namespace wowmod {
namespace win {

namespace {

Runtime g_runtime;
std::mutex g_runtime_mutex;

std::string env_string(const wchar_t* name) {
  DWORD n = GetEnvironmentVariableW(name, nullptr, 0);
  if (n == 0) return "";
  std::wstring buf(n, L'\0');
  GetEnvironmentVariableW(name, buf.data(), n);
  if (!buf.empty() && buf.back() == L'\0') buf.pop_back();
  return normalize_path(wide_to_utf8(buf));
}

std::string temp_dir_for_pid() {
  wchar_t tmp[MAX_PATH + 1] = {0};
  DWORD n = GetTempPathW(MAX_PATH, tmp);
  if (n == 0 || n > MAX_PATH) return "";
  std::wstring base(tmp, n);
  return normalize_path(wide_to_utf8(base) + "/wowmod-" + std::to_string(GetCurrentProcessId()));
}

std::string norm_lower(const std::wstring& w) { return to_lower(normalize_path(wide_to_utf8(w))); }

// 判断一个绝对（含 NT 设备形式）路径是否"看起来在游戏目录里"。
bool seems_under_game(const std::string& p, const std::string& rel, const Runtime& rt) {
  if (p.empty()) return false;
  // 相对路径（不带前导 / 或盘符）
  if (!(p[0] == '/' || (p.size() > 1 && p[1] == ':'))) return true;
  for (const auto& pre : rt.prefixes) if (starts_with(p, pre)) return true;
  // NT 设备路径：\Device\HarddiskVolumeX\... 或 \??\D:\...
  if (starts_with(p, "/?\?/") || p.find("harddiskvolume") != std::string::npos) {
    if (p.size() >= rel.size() + 1) return true;
  }
  // 兜底：路径里出现游戏目录的最后一段（例如 World of Warcraft / _retail_）
  if (!rt.game_tail.empty() && p.find("/" + rt.game_tail) != std::string::npos) return true;
  return false;
}

std::optional<std::string> strip_known_prefix(const std::string& p, const Runtime& rt) {
  for (const auto& pre : rt.prefixes) {
    if (starts_with(p, pre)) return p.substr(pre.size());
  }
  return std::nullopt;
}

}  // namespace

Runtime& runtime() { return g_runtime; }

void dlog(const std::string& msg) {
  OutputDebugStringA(("[wowmod] " + msg + "\n").c_str());
}

bool init_runtime(void* self_module) {
  Runtime& rt = g_runtime;
  std::lock_guard<std::mutex> lock(g_runtime_mutex);
  if (rt.ready) return true;
  rt.self_module = self_module;

  // 1) 配置路径：启动器通过环境变量传入；否则用可执行文件目录下的 wowmod.json
  rt.config_path = env_string(L"WOWMOD_CONFIG");
  if (rt.config_path.empty()) rt.config_path = join_path(exe_dir_path(), "wowmod.json");
  if (!file_exists(rt.config_path)) {
    dlog("config not found: " + rt.config_path + " (using empty config)");
    rt.cfg.base_dir = exe_dir_path();
    rt.cfg.path = rt.config_path;
  } else if (!load_config(rt.config_path, &rt.cfg, &rt.diag)) {
    dlog("config parse failed: " + rt.diag.render(false));
  }

  // 2) 客户端探测（在进程内做，仍然只读磁盘文件）
  std::wstring exe_w(MAX_PATH * 4, L'\0');
  DWORD en = GetModuleFileNameW(nullptr, exe_w.data(), static_cast<DWORD>(exe_w.size()));
  std::string own_exe = en ? normalize_path(wide_to_utf8(std::wstring(exe_w.data(), en))) : "";
  if (rt.cfg.client.exe.empty()) rt.cfg.client.exe = own_exe;
  std::string target = !rt.cfg.client.exe.empty() && file_exists(rt.cfg.client.exe) ? rt.cfg.client.exe : own_exe;
  std::vector<uint8_t> exe_bytes;
  rt.ci = detect_client(target, &rt.diag, &exe_bytes);
  // hook 点必须来自"当前正在运行的这个 exe"，配置里若指向别的客户端则单独读它
  if (!own_exe.empty() && normalize_path(own_exe) != normalize_path(target)) {
    std::vector<uint8_t> running;
    if (read_binary_file(own_exe, &running, nullptr)) exe_bytes = std::move(running);
  }
  if (rt.cfg.client.game_dir.empty()) rt.cfg.client.game_dir = parent_path(own_exe);
  if (rt.ci.game_dir.empty()) rt.ci.game_dir = parent_path(own_exe);

  // 3) 映射表 + 覆盖表
  for (const auto& p : rt.cfg.mappings) rt.mappings.load_file(p, &rt.diag);
  rt.vfs.build(rt.cfg, rt.ci, rt.mappings, &rt.diag);

  // 4) 把内存生成文件落到私有临时目录（不碰游戏目录）
  rt.temp_dir = env_string(L"WOWMOD_TEMP");
  if (rt.temp_dir.empty()) rt.temp_dir = temp_dir_for_pid();
  if (!rt.temp_dir.empty()) rt.vfs.materialize_generated(rt.temp_dir, &rt.diag);

  // 5) hook 能力探测：用真实 exe 字节做特征匹配，找不到就退化为纯 VFS
  rt.hooks = plan_hooks(rt.cfg, rt.ci, exe_bytes, &rt.diag);

  // 6) 建立路径索引
  auto add_prefix = [&](const std::string& s) {
    std::string n = to_lower(normalize_path(s));
    while (!n.empty() && n.back() == '/') n.pop_back();
    if (!n.empty()) rt.prefixes.push_back(n + "/");
  };
  add_prefix(rt.cfg.client.game_dir);
  add_prefix(rt.ci.game_dir);
  add_prefix(parent_path(rt.cfg.client.game_dir));  // 客户端在 _retail_ 之类子目录时
  std::sort(rt.prefixes.begin(), rt.prefixes.end(), [](const std::string& a, const std::string& b) { return a.size() > b.size(); });
  rt.prefixes.erase(std::unique(rt.prefixes.begin(), rt.prefixes.end()), rt.prefixes.end());
  rt.game_tail = to_lower(file_name(rt.cfg.client.game_dir));

  for (const auto& h : rt.vfs.effective_entries()) {
    if (h.key.empty()) continue;
    rt.by_filename[to_lower(file_name(h.key))].push_back(h.key);
    std::string d = parent_path(h.key);
    while (!d.empty() && d != "." && d != "/") {
      rt.directories.push_back(d);
      d = parent_path(d);
    }
  }
  std::sort(rt.directories.begin(), rt.directories.end());
  rt.directories.erase(std::unique(rt.directories.begin(), rt.directories.end()), rt.directories.end());
  std::sort(rt.directories.begin(), rt.directories.end(), [](const std::string& a, const std::string& b) { return a.size() > b.size(); });

  // 7) 写一份启动日志（此时 hook 尚未安装）
  rt.log_path = rt.cfg.log.file;
  if (!rt.log_path.empty()) {
    std::string report = "wowmod 启动报告\n" + rt.ci.display() + "\n\n" +
                         "hook: " + rt.hooks.mode + " - " + rt.hooks.reason + "\n\n" +
                         rt.vfs.plan_text() + "\n" + rt.diag.render(false);
    write_text_file(rt.log_path, report, nullptr);
  }

  rt.ready = true;
  dlog("runtime ready: " + rt.ci.version_string + " / " + rt.hooks.mode + " / " +
       std::to_string(rt.vfs.effective_entries().size()) + " overlays");
  return true;
}

Redirect resolve_redirect(const std::wstring& requested) {
  Redirect out;
  Runtime& rt = g_runtime;
  if (!rt.ready || requested.empty()) return out;
  std::string p = norm_lower(requested);
  if (p.empty()) return out;

  std::string rel;
  if (auto r = strip_known_prefix(p, rt)) {
    rel = *r;
  } else if (!(p[0] == '/' || (p.size() > 1 && p[1] == ':'))) {
    rel = p;  // 相对路径
  } else {
    // NT 设备路径等：按文件名索引做后缀匹配
    std::string fn = to_lower(file_name(p));
    auto it = rt.by_filename.find(fn);
    if (it != rt.by_filename.end()) {
      for (const auto& key : it->second) {
        if (p.size() < key.size()) continue;
        size_t start = p.size() - key.size();
        if (p.compare(start, key.size(), key) != 0) continue;
        if (start > 0 && p[start - 1] != '/') continue;
        if (!seems_under_game(p, key, rt)) continue;
        rel = key;
        break;
      }
    }
  }
  if (rel.empty()) return out;
  // 去掉 NT 路径里可能残留的冒号等
  if (rel.size() > 2 && rel[1] == ':') rel = rel.substr(2);
  while (!rel.empty() && rel[0] == '/') rel.erase(0, 1);

  auto hit = rt.vfs.resolve_path(rel);
  if (!hit) return out;
  out.key = hit->key;
  if (hit->blocked) { out.kind = RedirectKind::Block; return out; }
  if (hit->real_path.empty()) return out;
  out.kind = RedirectKind::Replace;
  out.path = hit->real_path;
  return out;
}

std::optional<std::string> directory_key(const std::wstring& requested) {
  Runtime& rt = g_runtime;
  if (!rt.ready || requested.empty()) return std::nullopt;
  std::string p = norm_lower(requested);
  // 去掉通配符与尾部文件名
  size_t star = p.find_last_of("*?");
  if (star != std::string::npos) p = p.substr(0, star);
  std::string base = file_name(p);
  if (!base.empty() && (base.find('.') != std::string::npos)) p = parent_path(p);
  while (!p.empty() && p.back() == '/') p.pop_back();
  if (auto r = strip_known_prefix(p, rt)) return *r;
  if (!(p[0] == '/' || (p.size() > 1 && p[1] == ':'))) return p;
  for (const auto& d : rt.directories) {
    if (p.size() >= d.size() && p.compare(p.size() - d.size(), d.size(), d) == 0) return d;
  }
  return std::nullopt;
}

bool overlay_is_directory(const std::string& dir_key, const std::string& name) {
  Runtime& rt = g_runtime;
  std::string prefix = path_key(dir_key) + "/" + to_lower(name) + "/";
  for (const auto& h : rt.vfs.effective_entries()) {
    if (starts_with(h.key, prefix)) return true;
  }
  return false;
}

}  // namespace win
}  // namespace wowmod
#endif  // _WIN32
