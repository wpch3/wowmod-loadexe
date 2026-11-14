// 启动器跳板（Windows 可执行体里的 .pdata 覆盖技巧）——本文件只做字节生成，
// 因此可以在 Linux 上单元测试。
//
// 目的：让「真正的代码」在目标进程启动的最早期运行，且不经过
// CreateRemoteThread / LoadLibraryW / APC / SetWindowsHookEx。
//
// 原理：
//   Windows x64 可执行体里每个函数都有一条 .pdata 中的 RUNTIME_FUNCTION 记录
//   （BeginAddress / EndAddress / UnwindInfoAddress）。系统在【加载阶段】完成
//   地址修正（重定位绝对地址）之后，才可能调度任何用户线程或调用 DllMain。
//   因此：
//     1. 找一条 RUNTIME_FUNCTION，其 BeginAddress 落在有填充空隙的代码区，
//        且在它之前有足够的 0xCC/0x90 空间容纳我们的代码；
//     2. 把该记录 BeginAddress 改成填充区起点；
//     3. 在填充区写入：pushfq/push 全部寄存器/执行 payload/恢复/执行被顶替的
//        原始序言字节/jmp 回真实入口。
//   加载器做完重定位后，我们的代码就会在任何游戏逻辑之前执行。
//
// 这与「注入 DLL」的关键区别：不依赖内核/用户态的线程创建与模块加载路径，
// 因此不会被「远程线程被静默拒绝」那类现象卡住；也不需要 DLL 出现在模块表里。
//
// 风险与限制（必须知道）：
//   * 改写了目标 exe 的内存映像，属于完整性敏感区域；部分保护会校验 .pdata。
//   * 一旦写入不当，客户端会在启动阶段崩溃（而不是"什么都没发生"）。
//   * 因此本模块生成的是【完整可审计的字节】，并且要求调用方显式开启。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace wowmod {

struct PdataEntry {
  uint32_t begin_rva = 0;
  uint32_t end_rva = 0;
  uint32_t unwind_rva = 0;
};

struct RelocInfo {
  uint32_t rva = 0;       // 被重定位字段的位置（RVA）
  uint16_t type = 0;      // IMAGE_REL_BASED_DIR64 = 10
};

struct PeLayout {
  bool ok = false;
  std::string error;
  uint64_t image_base = 0;
  uint32_t size_of_image = 0;
  uint32_t entry_rva = 0;
  // 区段（含节区对齐的空隙）
  struct Section {
    std::string name;
    uint32_t va = 0;
    uint32_t vsize = 0;
    uint32_t raw_size = 0;
    uint32_t raw_ptr = 0;
    uint32_t characteristics = 0;
    bool executable() const { return (characteristics & 0x20000000u) != 0; }
    bool writable() const { return (characteristics & 0x80000000u) != 0; }
  };
  std::vector<Section> sections;
  std::vector<PdataEntry> pdata;      // 仅 x64，已按 begin 排序
  std::vector<RelocInfo> relocs;
  uint32_t pdata_section_va = 0;
  uint32_t pdata_entries_off = 0;     // .pdata 表在文件中的偏移（用于回写）

  // RVA -> 文件偏移（不在任何区段的 raw 数据内时返回 SIZE_MAX）
  size_t rva_to_offset(uint32_t rva) const;
  const Section* section_of(uint32_t rva) const;
};

// 解析磁盘 PE（未映射视图）。
PeLayout parse_pe_file(const std::vector<uint8_t>& file);

struct StubPlan {
  bool ok = false;
  std::string reason;
  PdataEntry entry;            // 被改写的 RUNTIME_FUNCTION
  uint32_t begin_field_rva = 0;// BeginAddress 字段的【文件偏移】（用于回写）
  uint32_t cave_rva = 0;       // 填充区起点（新 BeginAddress）
  size_t cave_size = 0;
  uint32_t code_size = 0;      // 需要写入的字节数

  // 生成好的机器码（尚未填入 payload 地址）
  std::vector<uint8_t> stub_code;
  std::vector<std::pair<int, std::string>> patch_slots;  // 偏移 -> 需要的量
};

// 在 exe 里规划一个「早期执行跳板」。
//   min_cave        —— 需要的填充空间（>= payload 包装 + 原始序言）
//   require_no_reloc—— 填充区不能含任何重定位项（默认 true）
StubPlan plan_launcher_stub(const PeLayout& pe, const std::vector<uint8_t>& file,
                            size_t min_cave = 96, bool require_no_reloc = true);

// 生成跳板机器码。payload_va 是目标进程内要调用的函数绝对地址；
// stub_va 是填充区在目标进程内的绝对地址（用于 RIP 相对调用与跳回计算）。
std::vector<uint8_t> build_launcher_stub(uint64_t payload_va, uint64_t stub_va,
                                         const std::vector<uint8_t>& stolen_prologue);

// 把 payload 参数写进跳板（payload 用一个固定寄存器接收 stub_va，便于 payload 自定位）。
struct LauncherStubConfig {
  uint64_t payload_va = 0;
  uint64_t stub_va = 0;
  std::vector<uint8_t> stolen_prologue;  // 被顶替的原始字节（执行 payload 后补上）
};

std::vector<uint8_t> build_launcher_stub_code(const LauncherStubConfig& cfg);

}  // namespace wowmod
