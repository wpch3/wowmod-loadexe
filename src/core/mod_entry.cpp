// 可移植的路径规整：见 include/wowmod/mod_entry.hpp。
// SPDX-License-Identifier: MIT
#include "wowmod/mod_entry.hpp"

#include <algorithm>
#include <cctype>

namespace wowmod {
namespace win {

// 把游戏相对路径规整成客户端期望的形式：
//   * 反斜杠 -> 正斜杠
//   * 全部小写（客户端内部按小写查表）
//   * 去掉开头的 ./ 或 /
// 注意：**不要去掉空格**。listfile 里有 31944 条路径本身就带空格
// （例如 "Character/NightElf/Female/NightElfFemaleNakedPelvisSkin00_ 14.blp"），
// 那是官方命名，去掉空格反而永远匹配不到。
std::string normalize_game_path(const std::string& in) {
  std::string s = in;
  std::replace(s.begin(), s.end(), '\\', '/');
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  while (s.rfind("./", 0) == 0) s = s.substr(2);
  while (!s.empty() && s[0] == '/') s = s.substr(1);
  return s;
}

}  // namespace win
}  // namespace wowmod
