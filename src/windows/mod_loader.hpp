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

#include "wowmod/mod_entry.hpp"

namespace wowmod {
namespace win {

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
  // 观测点：stub 的调用次数 / 命中次数（u64，在客户端进程里）。
  // 没有它们，"装好了但不生效"完全无法定位。
  uint64_t call_counter_va = 0;
  uint64_t hit_counter_va = 0;
  uint64_t trampoline_va = 0;

  // 第一半：NoJump
  bool branch_patched = false;
  size_t anticrash_patches = 0;   // Arctium PrepareAntiCrash 写入的补丁数
  size_t branch_count = 0;
};

// 已经准备好的数据侧（来自 mappings/files 目录，或来自 --mods 自包含扫描）。
// 两条来源产出的结构完全一样，安装流程只认这个。
// 持续观测 stub 计数（客户端整个生命周期内）。
//
// 【为什么必须以函数形式提供，而不是"装完读一次"】
// 客户端从启动到进角色选择要几十秒，装完后立刻读必然是 0 次，
// 那个结论会把人带偏（上一版就是这么错的）。
// 调用方应在客户端运行期间反复调用它，或至少在退出时调用一次。
struct StubStats {
  uint64_t calls = 0;
  uint64_t hits = 0;
  bool ok = false;   // 是否成功读到
};

StubStats read_stub_stats(HANDLE process, uint64_t call_counter_va, uint64_t hit_counter_va);

// ---- 后台 anti-crash：resume 之后继续等完整性校验函数被解密 ----
//
// 【为什么必须在 resume 之后做】
//
// 实测 12.0.7：进程挂起时主映像只有 ~53/260 页是明文，Integrity 特征码
// 命中 0 处。但客户端【确实会运行】完整性自检 —— 进世界几十秒后
// 以 0xC00000E5 / 断言终止，十五轮都是同一个断言。
// 结论：那个校验函数是惰性解密的，在我们扫描的那几秒还没解密。
//
// 所以正确的时序是：
//   1) 挂起时先装好 NoJump + hook（客户端要用的代码此刻已就绪）
//   2) resume，让客户端继续跑
//   3) 后台线程每 500ms 重扫 Integrity 特征码
//   4) 一旦命中 -> 立刻打 ret 0 补丁（并打印命中地址）
//
// 这条路径与 Arctium 的差别：Arctium 在解包完成瞬间一次性做完；
// 12.0.7 是惰性解密，只能等它自己走到。
void start_anticrash_watchdog(HANDLE process, std::string log_path);

struct ModLoaderOptions {
  // 是否同时打 Arctium 的证书补丁。只有连私有服务器才需要（客户端不校验
  // 登录服务器证书）。模组加载完全不需要，所以默认关。
  bool cert_patches = false;

  // 【诊断开关】是否装 anti-crash 补丁。
  //
  // 为什么需要：12.0.7 上 Integrity 特征码命中 0 处，只有 remap 命中 1 处。
  // 于是 anti-crash 只写了那 1 条"跳转错位"补丁 —— 这会让客户端的
  // remap 校验流程走到一个不一致的状态（跳转被挪了，但校验函数还在），
  // 反而可能是 0xC00000E5 的来源。
  //
  // 关掉它，就能一次运行就区分"是 anti-crash 害的"还是"NoJump/跳板害的"。
  bool no_anticrash = false;

  // 只装跳板、不打 NoJump。用于区分两半各自的影响。
  bool no_jump_patches = false;
};

struct ModDataSet {
  std::vector<ModEntry> entries;
  std::string files_dir;      // 绝对路径：表里存的路径必须落在它下面
  std::string source_note;    // "mappings/files" 或 "--mods 自包含"
};

// 跳板实现选择。
enum class StubKind {
  // 逐字节照抄 Arctium：12 字节表项、50 字节固定 stub、
  // 未命中返回 0、负 id 执行原始指令。
  kArctium,
  // 本项目生成器：16 字节表项、命中走 ret、未命中跳 trampoline。
  // 已被 x64sim 逐条验证（含 1096 项表的最后一项）。
  kNative,
};

// 完整安装：读数据 -> 装查表跳板 -> 打 NoJump。
//
// wait_ms 用于等代码解密；12.0.7 的 .text 是按页惰性解密的，
// 在密文上扫描得到的命中是随机字节，必须等到明文比例足够。
ModLoaderResult install_mod_loader(HANDLE process, const std::string& wowmod_dir,
                                   uint32_t wait_ms,
                                   StubKind kind = StubKind::kArctium);

// 同一套安装流程，但数据侧由调用方直接给出（--mods 自包含模式用）。
// wowmod_dir 只用来放报告；数据不再从 <wowmod_dir>/mappings 读。
ModLoaderResult install_mod_loader_with_data(HANDLE process, const std::string& wowmod_dir,
                                             const ModDataSet& data, uint32_t wait_ms,
                                             StubKind kind = StubKind::kArctium,
                                             const ModLoaderOptions& opts = {});

std::string format_mod_loader_report(const ModLoaderResult& r);

}  // namespace win
}  // namespace wowmod
#endif
