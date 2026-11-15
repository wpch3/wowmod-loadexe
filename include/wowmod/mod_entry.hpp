// 一条「FileDataID -> 本地文件」映射。与 Windows 无关，可移植。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <string>

namespace wowmod {
namespace win {

// 把游戏相对路径规整成客户端期望的形式（反斜杠->正斜杠、小写，
// 但【不去空格】—— listfile 里有 3 万多条路径本身就带空格）。
std::string normalize_game_path(const std::string& in);

struct ModEntry {
  uint64_t file_data_id = 0;
  std::string game_path;    // 游戏内相对路径（mappings 里写的那个）
  std::string local_path;   // 磁盘上的绝对路径
  bool file_exists = false;
};

}  // namespace win
}  // namespace wowmod
