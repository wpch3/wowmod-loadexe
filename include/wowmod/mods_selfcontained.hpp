// --mods 目录 / --listfile 模式：不需要任何外部脚本和 python。
//
// 用户要的是「一个完整的 exe」。Arctium 的形态是
//     exe + mappings\*.txt + files\      （三个东西都在同一目录）
// 我们的 wowmod-load.cmd 走的是 --workdir <游戏目录>\wowmod，
// 要求先用 wowmod-mod.cmd + python 生成 mappings/ 和 files/。
//
// 这一层把同样的工作搬进 exe 本身：
//   * 直接扫 --mods 指向的模组目录（支持用户手上那三种真实形状：
//     Character\...、T21...\item\...、Xxx Mount\Creature\...、
//     以及 Wrath NPC Pack\Textures\BakedNpcTextures\...）
//   * 用 --listfile 的 "id;path" 把每个文件解析成 FileDataID
//     （精确 -> _HD 变体 -> 文件名+尾部目录打分，重名则拒绝，绝不乱猜）
//   * 产出的 ModEntry 与 load_mappings() 完全同构，
//     所以后面的安装流程一个字都不用改。
//
// 关键语义与 Arctium 一致：表里存的是【磁盘绝对路径】，
// 因为客户端拿到的是路径指针，要能直接打开。
// SPDX-License-Identifier: MIT
#pragma once

// 注意：这个模块【不需要 windows.h】。它只做「目录树 + listfile -> 条目」，
// 放在 src/windows 下是因为它服务于 Windows 启动器，但保持可移植，
// 以便测试在没有 Windows 的环境里也能验证解析逻辑。
#include <string>
#include <vector>

#include "wowmod/mod_entry.hpp"

namespace wowmod {
namespace win {

struct SelfContainedReport {
  bool ok = false;
  std::string error;
  size_t files_scanned = 0;      // 扫到的文件总数
  size_t matched = 0;            // 解析出 FileDataID 的
  size_t missing = 0;            // 解析不出来的
  size_t ambiguous = 0;          // 重名、无法确定（拒绝）
  size_t duplicates = 0;         // 同一 id 多个本地文件，已各留一条
  size_t by_exact = 0;      // 精确（含补上游戏前缀）
  size_t by_prefix = 0;     // 其中有多少条是靠「补上 character/ 这类前缀」命中的
  size_t by_hd = 0;
  size_t by_name = 0;
  std::vector<ModEntry> entries;
  std::vector<std::string> unresolved;   // 前若干条无法解析的路径
  std::string game_root;                 // 推断出来的相对路径基准
};

// mods_dir : 模组目录（可以就是游戏根，也可以是某个包）
// listfile : 一个或多个 "FileDataID;路径" 文件（用 ';' 分隔的多路径）
SelfContainedReport build_selfcontained_mods(const std::string& mods_dir,
                                            const std::vector<std::string>& listfiles);

// 把多个 listfile 路径（用 ';' 拼接）拆开。
std::vector<std::string> split_listfiles(const std::string& spec);

}  // namespace win
}  // namespace wowmod
