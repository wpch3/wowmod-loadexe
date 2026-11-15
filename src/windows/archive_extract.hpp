// 压缩包解压：用户手上的模组几乎都是 .zip / .rar / .7z。
//
// 为什么放在应用里：用户拿到的是「T21WarriorNSFW.rar」这种东西。
// 如果要求他先自己解压、还要"解到正确的那一层"，那前面所有为了避免
// 猜路径而写的代码全都白费 —— 这层不该由用户理解。
//
// 实现方式（不重新发明解压器）：
//   * .zip 用系统自带的 shell API（Windows XP 起就有，零依赖）
//   * .rar / .7z 找本机已装的 WinRAR / 7-Zip 命令行，静默调用
// 都不可用时返回明确原因，让用户知道是"缺什么"而不是"程序坏了"。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32

#include <functional>
#include <string>
#include <vector>

namespace wowmod {
namespace win {

struct ExtractResult {
  bool ok = false;
  std::string error;
  std::string out_dir;          // 解压目标目录
  size_t files = 0;             // 解出来的文件数（0 表示无法统计但不代表失败）
  std::string tool;             // 实际用的工具："shell" / "7z" / "winrar"
};

// 解压 archive 到 out_dir。on_line 收到工具输出的每一行（用于日志）。
ExtractResult extract_archive(const std::string& archive, const std::string& out_dir,
                              std::function<void(const std::string&)> on_line);

// 从文件名猜一个目录名（去掉扩展名、去掉非法字符）
std::string archive_stem(const std::string& archive);

}  // namespace win
}  // namespace wowmod
#endif
