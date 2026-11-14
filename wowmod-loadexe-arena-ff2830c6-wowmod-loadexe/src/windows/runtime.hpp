// 注入 DLL 的共享运行时状态。所有"版本相关"决策在启动时由磁盘数据算出。
// SPDX-License-Identifier: MIT
#pragma once

#ifdef _WIN32

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "wowmod/config.hpp"
#include "wowmod/hooks.hpp"
#include "wowmod/mapping.hpp"
#include "wowmod/util.hpp"
#include "wowmod/vfs.hpp"
#include "wowmod/version.hpp"

namespace wowmod {
namespace win {

enum class RedirectKind { None, Replace, Block };

struct Redirect {
  RedirectKind kind = RedirectKind::None;
  std::string path;  // UTF-8 绝对路径（Replace 时有效）
  std::string key;   // 命中的 game-relative key
};

struct Runtime {
  Config cfg;
  ClientInfo ci;
  MappingTable mappings;
  Vfs vfs;
  HookPlan hooks;
  Diagnostics diag;
  std::string config_path;
  std::string temp_dir;
  std::string log_path;
  std::string game_tail;
  std::vector<std::string> prefixes;                                  // 小写、以 '/' 结尾
  std::unordered_map<std::string, std::vector<std::string>> by_filename;
  std::vector<std::string> directories;                               // 覆盖表涉及的目录（小写）
  void* self_module = nullptr;
  bool ready = false;
};

Runtime& runtime();

// 在 DllMain 中调用：读配置 -> 探测 -> 构建覆盖表 -> 生成内存文件。
// 此函数内不得触发任何被 hook 的 API（hook 在它之后才安装）。
bool init_runtime(void* self_module);

// 只使用 OutputDebugStringA，避免任何文件 I/O 递归。
void dlog(const std::string& msg);

// 把客户端请求的路径（DOS / NT / 相对路径）解析成覆盖目标。
Redirect resolve_redirect(const std::wstring& requested);

// 目录枚举用：把请求目录变成 game-relative 目录 key。
std::optional<std::string> directory_key(const std::wstring& requested);
bool overlay_is_directory(const std::string& dir_key, const std::string& name);

}  // namespace win
}  // namespace wowmod

#endif  // _WIN32
