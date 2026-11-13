// wowmod-loadexe - WoW Arctium-style loader development tree
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wowmod {

// ---------- 字符串 ----------
std::string trim(std::string_view s);
std::string to_lower(std::string_view s);
std::string to_upper(std::string_view s);
bool iequals(std::string_view a, std::string_view b);
bool starts_with(std::string_view s, std::string_view prefix);
bool ends_with(std::string_view s, std::string_view suffix);
std::vector<std::string> split(std::string_view s, char sep);
std::vector<std::string> split_ws(std::string_view s);
std::string replace_all(std::string s, std::string_view from, std::string_view to);
std::string join(const std::vector<std::string>& parts, std::string_view sep);
bool parse_u64(std::string_view s, uint64_t* out, int base = 10);
bool parse_i64(std::string_view s, int64_t* out);
std::string to_hex(uint64_t v, int width = 0);
std::string bytes_to_ansi_path(const std::string& utf8_or_local);

// Wildcard match: '*' matches any sequence (including '/' when allow_slash),
// '?' matches one char, "**" is treated like '*'. Case-insensitive option.
bool wildcard_match(std::string_view pattern, std::string_view text, bool ci = true);

// ---------- 路径 ----------
// 所有内部 key 使用 '/'，小写，无前导 './'，无重复 '/'。
std::string normalize_path(std::string_view p);
std::string path_key(std::string_view p);
std::string join_path(std::string_view a, std::string_view b);
std::string parent_path(std::string_view p);
std::string file_name(std::string_view p);
std::string file_stem(std::string_view p);
std::string file_extension(std::string_view p);
bool is_absolute_path(std::string_view p);
// 把 path 变成相对于 base 的 game-relative key；不属于 base 时返回 nullopt。
std::optional<std::string> relative_key(std::string_view base, std::string_view path);
std::string to_native_path(std::string_view p);      // POSIX: unchanged; Win: '/' -> '\\'
std::string absolute_path(std::string_view p);

// ---------- 文件 ----------
bool file_exists(const std::string& p);
bool dir_exists(const std::string& p);
bool read_text_file(const std::string& p, std::string* out, std::string* err);
bool read_binary_file(const std::string& p, std::vector<uint8_t>* out, std::string* err);
bool write_text_file(const std::string& p, const std::string& text, std::string* err);
// 递归列出普通文件（相对 root 的路径，使用 '/' 分隔），按字典序返回。
std::vector<std::string> list_files_recursive(const std::string& root, std::string* err);
uint64_t file_size(const std::string& p);
std::string exe_dir_path();          // 当前可执行文件所在目录
std::string wide_to_utf8(std::wstring_view s);
std::wstring utf8_to_wide(std::string_view s);

// ---------- 诊断 ----------
enum class Level { Info, Warn, Error };

struct Diagnostic {
  Level level;
  std::string where;
  std::string message;
};

class Diagnostics {
 public:
  void info(std::string where, std::string msg);
  void warn(std::string where, std::string msg);
  void error(std::string where, std::string msg);
  bool has_errors() const;
  size_t count(Level l) const;
  const std::vector<Diagnostic>& items() const { return items_; }
  std::string render(bool color = false) const;
  void merge(const Diagnostics& other);

 private:
  std::vector<Diagnostic> items_;
};

}  // namespace wowmod
