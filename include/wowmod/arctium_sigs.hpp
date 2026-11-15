// Arctium 公开特征码表（可移植，不依赖 windows.h）。
//
// 来源：Arctium/WoW-Launcher（MIT）
//   src/Patterns/Windows.cs  -> CustomFileIdHook / LoadByFileId / LoadByFilePath
//   src/Patches/Windows.cs   -> NoJump = { 0x00, 0x00, 0x00, 0x00 }
//
// 这里只放数据，不放平台代码，这样主机上的单元测试也能校验表本身
// （能否解析、改写偏移是否合理），而真正的客户端匹配结果只在 Windows 上现场产生。
//
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <vector>

namespace wowmod {

// Arctium 的改写方式：把 patch_offset 处的 4 字节跳转条件改成 0，
// 让函数不再进入「从 CASC 加载」的分支。
struct ArctiumSignatureSpec {
  const char* name;
  const char* pattern;   // IDA 风格，?? = 通配
  int patch_offset;      // 从匹配起点到要改写的分支偏移
  const char* note;

  // ---- 可选：强校验信息 ----
  //
  // 为什么需要：Arctium 的原始特征码通配位极多（17 字节里 13 个 ??），
  // 只约束了 4 个字节。它只扫「主模块」且默认唯一，所以够用；
  // 而我们为了覆盖壳把代码解密到别的分配的情况，要扫全进程 200+ MB，
  // 同一段代码的多个副本 + 其他函数的巧合序言会让它命中十几处。
  //
  // 所以补两条硬约束：
  //   strong_pattern : 由实测反汇编导出、【无通配】的长签名，全映像唯一
  //   known_rva      : 在已确证的客户端版本上的 RVA，只在该版本上作为附加校验
  // 两者都为空时，行为退回「纯 Arctium 特征码」，即旧逻辑。
  const char* strong_pattern = nullptr;  // 可空
  uint32_t known_rva = 0;                // 0 = 不知道
  uint32_t known_build = 0;              // 该 known_rva 对应的 build 号，0 = 通用
};

// ---- 站点窗口校验（纯函数，便于单测）----
//
// 输入：现场从目标进程读到的 16 字节窗口 `live`，
//       以及全映像缓存的指针 `scanned`（扫描阶段 ReadProcessMemory 的结果）
//       和该站点的 rva_in_image。
// 输出：应当用于判定 je 的窗口。
//
// 为什么需要：现场 ReadProcessMemory 失败时 read_exact 会【静默返回全 0】，
// 于是 "前 6 字节里没有 0F 84" -> 规划失败 -> NoJump 装不上。
// 线上出现过 "诊断（用缓存字节）说位置正确，规划（用现场字节）说找不到" 的矛盾。
// 判据用 "能否定位到 je"，而不是猜数据是否有效。
bool resolve_site_window(std::vector<uint8_t> live,
                         const std::vector<uint8_t>* scanned,
                         uint64_t rva_in_image);

// ---- 命中筛选（纯函数，便于单测）----
//
// Arctium 的 FindPattern 只做字节匹配，**从不查 VirtualQueryEx 的保护位**。
// 我们过去在挑选命中时要求 has_rx（命中页可执行），后果是：
//     第 2 轮: CustomFileIdHook 1 处 (可执行 否, 语义分 0/8)
//     全轮结束 hook 目标为空 -> 跳板没装 -> 模组不加载
// 壳把 .text 映射成 PAGE_READWRITE(0x04)，所以每一个命中都会被这条规则丢掉。
// 写入时本来就会临时改保护，命中页的原属性不是拒绝理由。
struct HitCandidate {
  uint64_t va = 0;
  int semantic_score = 0;
  bool executable = false;
};

// 从候选里选 hook 目标：分数最高者胜，同分取先到者。
// 注意：executable 不参与筛选（只用于日志措辞）。
uint64_t pick_hook_target(const std::vector<HitCandidate>& cands, int* score_out);

// ---- WaitForUnpack 的第二步（纯函数，便于单测）----
//
// 上游 Arctium Launcher.cs：
//   initOffset += BitConverter.ToUInt32(memory.Read(initOffset + base + 2, 4), 0) + 10;
//   while (memory.Read(initOffset + base, 1)?[0] == null ||
//          memory.Read(initOffset + base, 1)?[0] == 0) ...
//
// Init 的特征码是 `C7 05 <rel32> 01 00 00 00`（mov dword ptr [x], 1）。
// 特征码出现只证明【这段代码被解密】，不证明客户端【执行过它】。
// 真正的"解包完成"信号是 x 处的字节变成非 0。
//
// 返回：标记地址（init_va + 10 + rel32）。读不到返回 0。
uint64_t compute_init_flag_address(uint64_t init_va, int32_t rel32);

// 判据：解包是否完成。flag_read_ok=false 表示读不到，视为未完成。
bool unpack_is_done(bool init_seen, bool flag_read_ok, uint8_t flag_value);

// 指针失效风险：返回的是静态表的引用，进程生命周期内有效。
const std::vector<ArctiumSignatureSpec>& arctium_signature_specs();

}  // namespace wowmod
