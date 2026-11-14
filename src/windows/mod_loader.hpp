// 模组加载器：把 wowmod\mappings\*.txt + wowmod\files\ 真正接到客户端里。
//
// 这是本项目长期缺失的「第二半」。Arctium 的机制是两半：
//   第一半：NoJump 改掉 je 的 rel32          -> 让客户端不去 CASC 取
//   第二半：idAlloc 查表跳板                   -> 让客户端能从本地路径取
// 之前只做了第一半，所以无论怎么调都不可能生效。
//
// 本文件负责：
//   1. 读 mappings/*.txt（"id;path"，允许 # 注释与空行）
//   2. 校验 files/ 下对应文件真的存在（缺一个都不装，避免半套映射）
//   3. 在 CustomFileIdHook 命中处装查表跳板
//   4. 同时打上两条 NoJump 分支补丁
//
// 安全策略：任何一步不满足就整体不装，并明确说明原因。宁可不动，不留半套。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wowmod {
namespace win {

struct ModEntry {
  uint64_t file_data_id = 0;
  std::string game_path;    // 游戏内相对路径（mappings 里写的那个）
  std::string local_path;   // 磁盘上的绝对路径
  bool file_exists = false;
};

struct MappingLoadReport {
  size_t files_read = 0;         // 读到的 mappings/*.txt 数量
  size_t lines_total = 0;
  size_t parsed = 0;             // 成功解析的 "id;path" 行
  size_t skipped_comment = 0;
  size_t bad_lines = 0;
  size_t missing_local = 0;      // 磁盘上没有对应文件
  std::vector<ModEntry> entries; // 只保留 file_exists == true 的
  std::vector<ModEntry> missing; // 统计用
  std::string error;
};

// 读 wowmod\mappings\*.txt + wowmod\files\。
// entries 只包含「磁盘上确实存在」的项，因为 idAlloc 里的路径一旦被返回，
// 客户端就会去读它；指向不存在的文件比不装更糟（会报错而不是回退）。
MappingLoadReport load_mappings(const std::string& wowmod_dir);

struct ModLoaderResult {
  bool ok = false;
  std::string error;
  std::vector<std::string> steps;

  // 数据侧
  size_t entries_loaded = 0;
  size_t entries_missing = 0;

  // 第二半：查表跳板
  bool hook_installed = false;
  uint64_t hook_target = 0;
  uint64_t id_table_va = 0;
  uint64_t string_blob_va = 0;
  uint64_t stub_va = 0;
  uint64_t trampoline_va = 0;

  // 第一半：NoJump
  bool branch_patched = false;
  size_t branch_count = 0;
};

// 完整安装：读数据 -> 装查表跳板 -> 打 NoJump。
//
// wait_ms 用于等代码解密；12.0.7 的 .text 是按页惰性解密的，
// 在密文上扫描得到的命中是随机字节，必须等到明文比例足够。
ModLoaderResult install_mod_loader(HANDLE process, const std::string& wowmod_dir,
                                   uint32_t wait_ms);

std::string format_mod_loader_report(const ModLoaderResult& r);

}  // namespace win
}  // namespace wowmod
#endif
