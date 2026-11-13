// SPDX-License-Identifier: MIT
#include "wowmod/util.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;
namespace wowmod {

std::string trim(std::string_view s) {
  size_t a = 0, b = s.size();
  while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return std::string(s.substr(a, b - a));
}

std::string to_lower(std::string_view s) {
  std::string r(s);
  std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return r;
}

std::string to_upper(std::string_view s) {
  std::string r(s);
  std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  return r;
}

bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) return false;
  }
  return true;
}

bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::vector<std::string> split(std::string_view s, char sep) {
  std::vector<std::string> out;
  size_t start = 0;
  while (start <= s.size()) {
    size_t pos = s.find(sep, start);
    if (pos == std::string_view::npos) {
      out.emplace_back(s.substr(start));
      break;
    }
    out.emplace_back(s.substr(start, pos - start));
    start = pos + 1;
  }
  return out;
}

std::vector<std::string> split_ws(std::string_view s) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    size_t start = i;
    while (i < s.size() && !std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    if (i > start) out.emplace_back(s.substr(start, i - start));
  }
  return out;
}

std::string replace_all(std::string s, std::string_view from, std::string_view to) {
  if (from.empty()) return s;
  size_t pos = 0;
  while ((pos = s.find(from, pos)) != std::string::npos) {
    s.replace(pos, from.size(), to);
    pos += to.size();
  }
  return s;
}

std::string join(const std::vector<std::string>& parts, std::string_view sep) {
  std::string out;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i) out.append(sep);
    out.append(parts[i]);
  }
  return out;
}

bool parse_u64(std::string_view s, uint64_t* out, int base) {
  if (!out) return false;
  std::string t = trim(s);
  if (t.empty()) return false;
  // 允许 0x 前缀和尾随 'h'（IDA 风格）
  int b = base;
  if (starts_with(to_lower(t), "0x")) { b = 16; t = t.substr(2); }
  if (!t.empty() && (t.back() == 'h' || t.back() == 'H')) { b = 16; t.pop_back(); }
  uint64_t v = 0;
  auto res = std::from_chars(t.data(), t.data() + t.size(), v, b);
  if (res.ec != std::errc() || res.ptr != t.data() + t.size()) return false;
  *out = v;
  return true;
}

bool parse_i64(std::string_view s, int64_t* out) {
  if (!out) return false;
  std::string t = trim(s);
  if (t.empty()) return false;
  int64_t v = 0;
  auto res = std::from_chars(t.data(), t.data() + t.size(), v, 10);
  if (res.ec != std::errc() || res.ptr != t.data() + t.size()) return false;
  *out = v;
  return true;
}

std::string to_hex(uint64_t v, int width) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(v));
  std::string s(buf);
  if (width > 0 && s.size() < static_cast<size_t>(width)) s.insert(0, width - s.size(), '0');
  return s;
}

// 递归通配符匹配（'*' 可跨 '/'，'?' 匹配单字符），大小写不敏感。
static bool wild_rec(std::string_view p, std::string_view t, bool ci) {
  size_t pi = 0, ti = 0, star_p = std::string_view::npos, star_t = 0;
  while (ti < t.size()) {
    if (pi < p.size() && p[pi] == '*') {
      // 折叠连续的 '*'
      while (pi < p.size() && p[pi] == '*') ++pi;
      star_p = pi;
      star_t = ti;
      if (pi == p.size()) return true;
      continue;
    }
    bool match = false;
    if (pi < p.size()) {
      char pc = p[pi];
      char tc = t[ti];
      if (ci) { pc = static_cast<char>(std::tolower(static_cast<unsigned char>(pc))); tc = static_cast<char>(std::tolower(static_cast<unsigned char>(tc))); }
      match = (pc == '?' || pc == tc);
    }
    if (match) { ++pi; ++ti; continue; }
    if (star_p != std::string_view::npos) {
      pi = star_p;
      ti = ++star_t;
      continue;
    }
    return false;
  }
  while (pi < p.size() && p[pi] == '*') ++pi;
  return pi == p.size();
}

bool wildcard_match(std::string_view pattern, std::string_view text, bool ci) {
  return wild_rec(normalize_path(pattern), normalize_path(text), ci);
}

std::string normalize_path(std::string_view p) {
  std::string s = replace_all(std::string(p), "\\", "/");
  std::vector<std::string> parts;
  bool absolute = false;
  bool drive = false;
  std::string prefix;
  if (!s.empty() && s[0] == '/') { absolute = true; prefix = "/"; }
  // Windows 盘符 "C:/..."
  if (s.size() >= 2 && std::isalpha(static_cast<unsigned char>(s[0])) && s[1] == ':') {
    drive = true;
    prefix = s.substr(0, 2);
    s = s.substr(2);
    if (!s.empty() && s[0] == '/') absolute = true;
  }
  // UNC 前缀 //server/share
  if (!drive && starts_with(s, "//")) { prefix = "//"; absolute = true; s = s.substr(2); }
  for (const auto& seg : split(s, '/')) {
    if (seg.empty() || seg == ".") continue;
    if (seg == "..") {
      if (!parts.empty() && parts.back() != "..") parts.pop_back();
      else if (!absolute) parts.push_back("..");
    } else {
      parts.push_back(seg);
    }
  }
  std::string out = prefix;
  if (drive && absolute) out += "/";
  else if (absolute && prefix == "/") out = "/";
  out += join(parts, "/");
  if (out.empty()) return ".";
  return out;
}

std::string path_key(std::string_view p) { return to_lower(normalize_path(p)); }

std::string join_path(std::string_view a, std::string_view b) {
  if (a.empty()) return normalize_path(b);
  if (is_absolute_path(b)) return normalize_path(b);
  return normalize_path(std::string(a) + "/" + std::string(b));
}

std::string parent_path(std::string_view p) {
  std::string n = normalize_path(p);
  size_t pos = n.rfind('/');
  if (pos == std::string::npos) return "";
  if (pos == 0) return "/";
  return n.substr(0, pos);
}

std::string file_name(std::string_view p) {
  std::string n = normalize_path(p);
  size_t pos = n.rfind('/');
  return pos == std::string::npos ? n : n.substr(pos + 1);
}

std::string file_stem(std::string_view p) {
  std::string f = file_name(p);
  size_t dot = f.rfind('.');
  return dot == std::string::npos ? f : f.substr(0, dot);
}

std::string file_extension(std::string_view p) {
  std::string f = file_name(p);
  size_t dot = f.rfind('.');
  return dot == std::string::npos ? "" : f.substr(dot);
}

bool is_absolute_path(std::string_view p) {
  std::string n = normalize_path(p);
  if (!n.empty() && n[0] == '/') return true;
  return n.size() >= 3 && std::isalpha(static_cast<unsigned char>(n[0])) && n[1] == ':' && n[2] == '/';
}

std::optional<std::string> relative_key(std::string_view base, std::string_view path) {
  std::string b = path_key(base);
  std::string p = path_key(path);
  while (!b.empty() && b.back() == '/') b.pop_back();
  if (b.empty()) return normalize_path(path);
  if (p == b) return std::string();
  if (starts_with(p, b + "/")) return p.substr(b.size() + 1);
  return std::nullopt;
}

std::string to_native_path(std::string_view p) {
#ifdef _WIN32
  return replace_all(normalize_path(p), "/", "\\");
#else
  return normalize_path(p);
#endif
}

std::string absolute_path(std::string_view p) {
  std::error_code ec;
  fs::path fp = fs::absolute(fs::path(std::string(p)), ec);
  if (ec) return normalize_path(p);
  return normalize_path(fp.lexically_normal().string());
}

bool file_exists(const std::string& p) {
  std::error_code ec;
  return fs::is_regular_file(fs::path(p), ec);
}

bool dir_exists(const std::string& p) {
  std::error_code ec;
  return fs::is_directory(fs::path(p), ec);
}

bool read_text_file(const std::string& p, std::string* out, std::string* err) {
  std::ifstream f(p, std::ios::binary);
  if (!f) { if (err) *err = "无法打开文件: " + p; return false; }
  std::ostringstream ss;
  ss << f.rdbuf();
  *out = ss.str();
  return true;
}

bool read_binary_file(const std::string& p, std::vector<uint8_t>* out, std::string* err) {
  std::ifstream f(p, std::ios::binary);
  if (!f) { if (err) *err = "无法打开文件: " + p; return false; }
  out->assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
  return true;
}

bool write_text_file(const std::string& p, const std::string& text, std::string* err) {
  std::error_code ec;
  fs::create_directories(fs::path(p).parent_path(), ec);
  std::ofstream f(p, std::ios::binary | std::ios::trunc);
  if (!f) { if (err) *err = "无法写入文件: " + p; return false; }
  f.write(text.data(), static_cast<std::streamsize>(text.size()));
  return true;
}

std::vector<std::string> list_files_recursive(const std::string& root, std::string* err) {
  std::vector<std::string> out;
  std::error_code ec;
  if (!fs::is_directory(fs::path(root), ec)) {
    if (err) *err = "不是目录: " + root;
    return out;
  }
  for (fs::recursive_directory_iterator it(fs::path(root), fs::directory_options::skip_permission_denied, ec), end;
       !ec && it != end; it.increment(ec)) {
    if (it->is_regular_file(ec)) {
      out.push_back(normalize_path(fs::relative(it->path(), fs::path(root), ec).string()));
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

uint64_t file_size(const std::string& p) {
  std::error_code ec;
  auto s = fs::file_size(fs::path(p), ec);
  return ec ? 0 : static_cast<uint64_t>(s);
}

std::string exe_dir_path() {
#ifdef _WIN32
  std::vector<wchar_t> buf(32768);
  DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
  if (n == 0 || n >= buf.size()) return ".";
  return parent_path(wide_to_utf8(std::wstring(buf.data(), n)));
#else
  std::error_code ec;
  fs::path p = fs::read_symlink("/proc/self/exe", ec);
  if (ec) return ".";
  return normalize_path(p.parent_path().string());
#endif
}

std::string wide_to_utf8(std::wstring_view s) {
#ifdef _WIN32
  if (s.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
  return out;
#else
  std::string out;
  out.reserve(s.size() * 4);
  for (wchar_t wc : s) {
    uint32_t cp = static_cast<uint32_t>(wc);
    if (cp < 0x80) out.push_back(static_cast<char>(cp));
    else if (cp < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }
  return out;
#endif
}

std::wstring utf8_to_wide(std::string_view s) {
#ifdef _WIN32
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring out(static_cast<size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
  return out;
#else
  std::wstring out;
  size_t i = 0;
  while (i < s.size()) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    uint32_t cp = c; size_t len = 1;
    if (c >= 0xF0) { cp = c & 0x07; len = 4; }
    else if (c >= 0xE0) { cp = c & 0x0F; len = 3; }
    else if (c >= 0xC0) { cp = c & 0x1F; len = 2; }
    for (size_t k = 1; k < len && i + k < s.size(); ++k) cp = (cp << 6) | (static_cast<unsigned char>(s[i + k]) & 0x3F);
    out.push_back(static_cast<wchar_t>(cp));
    i += len;
  }
  return out;
#endif
}

void Diagnostics::info(std::string where, std::string msg) { items_.push_back({Level::Info, std::move(where), std::move(msg)}); }
void Diagnostics::warn(std::string where, std::string msg) { items_.push_back({Level::Warn, std::move(where), std::move(msg)}); }
void Diagnostics::error(std::string where, std::string msg) { items_.push_back({Level::Error, std::move(where), std::move(msg)}); }

bool Diagnostics::has_errors() const {
  return std::any_of(items_.begin(), items_.end(), [](const Diagnostic& d) { return d.level == Level::Error; });
}

size_t Diagnostics::count(Level l) const {
  return static_cast<size_t>(std::count_if(items_.begin(), items_.end(), [l](const Diagnostic& d) { return d.level == l; }));
}

void Diagnostics::merge(const Diagnostics& other) {
  items_.insert(items_.end(), other.items_.begin(), other.items_.end());
}

std::string Diagnostics::render(bool color) const {
  static const char* tags[] = {"信息", "警告", "错误"};
  static const char* colors[] = {"\033[36m", "\033[33m", "\033[31m"};
  std::string out;
  for (const auto& d : items_) {
    int l = static_cast<int>(d.level);
    if (color) out += colors[l];
    out += "[" + std::string(tags[l]) + "] ";
    if (!d.where.empty()) out += d.where + ": ";
    out += d.message;
    if (color) out += "\033[0m";
    out += "\n";
  }
  return out;
}

}  // namespace wowmod
