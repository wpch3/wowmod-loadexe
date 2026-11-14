// 客户端映像离线分析：字符串交叉引用、函数起点回退、hook 点规划。
//
// 存在的意义：Arctium 的参照实现把「特征 → 补丁点」写死成常量。12.0.7 换版后
// 那些常量全部失效，而 Firestorm 的加载壳在磁盘上还是加密的，静态扫描什么都找不到。
// 本模块不猜特征，而是从【真实解密后的映像】反推位置：
//   - 已知字符串（客户端自己会打印的 "Locally overridden files"、loose 文件路径）
//     → RIP 相对 lea/mov 的引用地址 → 引用它的函数
//   - 函数起点回退（int3/ret 填充 + 序言特征）
//   - hook 点规划：完整指令边界 + trampoline 可重定位性检查
//
// 全部是只读分析，不修改任何进程。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace wowmod {

// 一份已映射到内存的 PE 映像：文件偏移 == RVA。
struct ImageView {
  const uint8_t* data = nullptr;
  size_t size = 0;
  uint64_t base_va = 0;   // 映像在目标进程里的基址（用于把 RVA 变成 VA）

  bool valid() const { return data != nullptr && size != 0; }
  uint64_t va_of(size_t off) const { return base_va + off; }
};

// 一条 RIP 相对引用（lea/mov 之类）。
struct CodeRef {
  size_t at = 0;          // 指令起始文件偏移（== RVA）
  uint64_t target_va = 0; // 被引用的目标 VA
  size_t target_off = 0;  // 目标在映像内的偏移（越界时 == SIZE_MAX）
  std::string form;       // "lea" / "mov"
};

// 在映像里查找到某个数据地址的全部 RIP 相对代码引用。
// 实现策略：先在映像里搜索目标地址的低 4 字节，再回退验证前缀构成合法
// `REX lea/mov reg, [rip+disp32]`。复杂度 O(n)，40 MB 映像也在秒级。
// max_seconds：时间预算。这是 O(映像大小) 的全盘扫描，调用方在大映像上
// 必须设上限，否则标记数量 × 命中数量 会让总耗时爆炸。
std::vector<CodeRef> find_code_refs_to(const ImageView& img, uint64_t target_va,
                                      size_t max_hits = 4096, double max_seconds = 0.0);

// 一次全盘扫描同时解析多个目标地址的引用。分析阶段目标数是
// 「标记 × 命中」，逐个扫会变成上百次全盘遍历，必须用这个。
std::map<uint64_t, std::vector<CodeRef>> find_code_refs_to_many(
    const ImageView& img, const std::vector<uint64_t>& targets,
    size_t max_hits_per_target = 64, double max_seconds = 0.0);

// 在映像里查找某个字节串（ASCII 或 UTF-16LE）的全部出现位置。
std::vector<size_t> find_bytes(const ImageView& img, const std::string& needle,
                              bool utf16 = false, size_t max_hits = 256,
                              double max_seconds = 0.0);

// 从 pos 向前回退，找到最可能的函数起点。
// 判定顺序：紧邻的 int3/0x00/0xCC 对齐填充 → 序言特征 → 上游 ret 之后。
// 返回 SIZE_MAX 表示没找到。
size_t find_function_start(const ImageView& img, size_t pos, size_t max_back = 0x2000);

// 反汇编一小段（用于报告），每行 "RVA: bytes  mnemonic-ish"。
struct ShownInsn {
  size_t rva = 0;
  std::vector<uint8_t> bytes;
  std::string text;
  bool is_rip_relative = false;
  bool is_jump = false;
};
std::vector<ShownInsn> disassemble_window(const ImageView& img, size_t pos, size_t max_bytes = 96);

// ---- hook 点规划 ----
struct HookSitePlan {
  bool ok = false;
  size_t rva = 0;
  size_t copy_len = 0;           // 需要搬到 trampoline 的字节数（完整指令）
  bool relocatable = false;      // 搬运的指令能否重算相对位移
  bool has_rip_relative = false;
  bool has_jump = false;
  std::string reason;
  std::vector<ShownInsn> prologue;
};

// 在 rva 处规划一个 detour：至少覆盖 min_bytes，且必须落在完整指令边界上。
HookSitePlan plan_hook_site(const ImageView& img, size_t rva, size_t min_bytes = 14);

// ---- FileDataID 查找函数候选 ----
// 结构特征（与版本无关）：
//   * 一个 32 位比较 `cmp r/m32, r32`，其中 r/m 使用「基址 + 索引寄存器*4/8」寻址
//     —— 数组里按 id 线性查找的典型形状；
//   * 附近有 `test reg, reg` 或 `cmp ..., 0` 的 id 符号检查；
//   * 函数体在 ±96 字节内含 `ret`，且返回寄存器是 RAX/RCX（返回指针）。
// 这只是**候选**：真正确认要在运行期观察实参。
struct IdLookupCandidate {
  size_t rva = 0;          // 函数起点
  size_t cmp_rva = 0;      // 那个比较指令的位置
  int score = 0;
  int scale = 0;           // SIB index scale（4/8）
  std::string id_register; // 猜测的 id 参数寄存器（rdx/rcx/r8/...）
  std::string evidence;
  std::vector<ShownInsn> window;
};
// max_seconds：时间预算。对 100MB+ 的映像做全盘反汇编可能要几十秒，
// 必须设上限，否则调用方看起来就是卡死。0 表示不限制。
std::vector<IdLookupCandidate> scan_id_lookup_candidates(const ImageView& img,
                                                         size_t max_results = 32,
                                                         double max_seconds = 0.0);

// 把一个候选转成可读报告（文本）。
std::string render_candidates(const std::vector<IdLookupCandidate>& cands);

}  // namespace wowmod
