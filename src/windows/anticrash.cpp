// Arctium PrepareAntiCrash 的 Windows 侧实现。见 anticrash.hpp。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/anticrash.hpp"

#include <cstdio>
#include <cstring>
#include <string>

#include "wowmod/util.hpp"
#include "windows/detour.hpp"
#include "windows/scan_images.hpp"

namespace wowmod {
namespace win {

AntiCrashPlan plan_anti_crash(HANDLE process, bool cert_patches) {
  // 规划只基于【选定为客户端映像】的那一份。
  //
  // 以前是「取 size 最大的那块」。线上实测的后果：
  //   * 日志里主映像尺寸随轮次从 108 MB 跳到 256 MB —— 那不是 SizeOfImage，
  //     所以我们当时扫的根本不是客户端映像；
  //   * anti-crash 因此一条 Integrity/Remap 都没找到（报告里写「本次没有写入」）；
  //   * 而客户端一旦自己走到完整性校验，就直接 0xC00000E5 闪退。
  //
  // scan_process_images 现在第一件事就是用 PEB + PE 头确定映像
  // （见 src/core/image_select.cpp），返回列表的第 0 项就是它。
  AntiCrashPlan plan;
  const auto images = scan_process_images(process);
  if (images.empty()) {
    plan.error =
        "定位不到客户端映像（PEB 与区域表都没给出 PE 头自洽的映像）。"
        "这种情况下 anti-crash 无从规划 —— 不是「本版本没有这些校验」。";
    return plan;
  }
  // 【这里曾经有一处致命逻辑，必须记录】
  //
  // 旧代码在取到 images[0] 之后，又用一个 max-size 循环重新指向了
  // 「尺寸最大的那块内存」，把它覆盖掉了（具体写法见本文件 git 历史）。
  //
  // 上面刚把 images[0] 修成「PEB + PE 头确认过的客户端映像」，
  // 这三行立刻又把它覆盖成「size 最大的那块」—— 也就是那个假映像。
  // 线上实测证据：
  //     anti-crash 规划基于映像 0x00000000ffff0000，SizeOfImage 256 MB
  // 而同一轮里 hook 目标是 0x6ea06a0（= base + 0x33E06A0，真映像内）。
  // 两个数字来自【完全不同的映像】，所以 anti-crash 一条校验点都找不到，
  // 报告就写成「本版本可能没有这些校验」—— 完全是假原因。
  //
  // 现在只用 images[0]。它由 scan_process_images 用 PEB 基址 +
  // PE 头 SizeOfImage 自洽性选出，是唯一可信的那一份。
  const ScannedImage* main_img = &images[0];
  if (main_img->bytes.size() < 0x1000) {
    plan.error = "映像内容不可读（读到 " + std::to_string(main_img->bytes.size()) + " 字节）";
    return plan;
  }
  plan = plan_anti_crash_from_image(main_img->bytes, main_img->base, cert_patches);
  plan.notes.push_back("规划基于映像 0x" + to_hex(main_img->base, 16) + "，SizeOfImage " +
                       std::to_string(main_img->size / 1048576) + " MB，已读 " +
                       std::to_string(main_img->bytes.size() / 1048576) + " MB");
  return plan;
}

bool apply_anti_crash(HANDLE process, AntiCrashPlan* plan) {
  if (!plan) return false;
  if (!plan->ok) return false;
  size_t wrote = 0;
  for (const auto& p : plan->patches) {
    std::string err;
    DWORD old = 0;
    const size_t len = p.bytes.size();

    // 【VirtualProtectEx 的硬性要求，曾经写错】
    //   * lpAddress 必须是页对齐地址
    //   * dwSize 必须覆盖到「从该地址到该页末尾」的整个范围
    // 我过去直接传 (p.va, len) —— p.va 中途、len=5，都会被判
    // ERROR_INVALID_PARAMETER(87)。线上实测正是 87 失败。
    //
    // 正确做法：把地址按页下舍、把长度扩到覆盖这一页（甚至跨页时覆盖全部）。
    const uint64_t page_mask = 0xFFF;
    const uint64_t va_page = p.va & ~page_mask;
    const uint64_t end = p.va + len;
    const uint64_t end_page = (end + page_mask) & ~page_mask;
    const size_t prot_len = static_cast<size_t>(end_page - va_page);

    // 写前确认：这一页确实处在客户端映像范围内、且已提交。
    //
    // 只靠"规划时算出来的地址"不够 —— 一次错误的命中也会给出一个
    // 看起来合理的地址，然后在 VirtualProtectEx 处以 87 失败。
    // 先问内核这块内存是什么，能立刻区分「地址错」与「权限问题」。
    {
      MEMORY_BASIC_INFORMATION mbi;
      std::memset(&mbi, 0, sizeof(mbi));
      if (!VirtualQueryEx(process, reinterpret_cast<LPCVOID>(p.va), &mbi, sizeof(mbi))) {
        plan->notes.push_back("跳过 @" + p.name + "：VirtualQueryEx 失败 (err=" +
                             std::to_string(GetLastError()) + ")");
        continue;
      }
      if (mbi.State != MEM_COMMIT) {
        plan->notes.push_back("跳过 @" + p.name + "：该地址未提交 (State=0x" +
                             to_hex(mbi.State, 8) + ")");
        continue;
      }
      plan->notes.push_back("  " + p.name + ": 页 0x" + to_hex(va_page, 16) +
                           " State=committed Type=0x" + to_hex(mbi.Type, 8) +
                           " Protect=0x" + to_hex(mbi.Protect, 8));
    }

    if (!VirtualProtectEx(process, reinterpret_cast<void*>(va_page), prot_len,
                          PAGE_EXECUTE_READWRITE, &old)) {
      plan->notes.push_back("VirtualProtectEx 失败 @" + p.name + " (va=0x" +
                           to_hex(p.va, 16) + ", 保护 0x" + to_hex(va_page, 16) +
                           " 长度 " + std::to_string(prot_len) + "): GetLastError=" +
                           std::to_string(GetLastError()));
      continue;
    }
    const bool ok = write_remote(process, p.va, p.bytes.data(), len, &err);
    DWORD tmp = 0;
    VirtualProtectEx(process, reinterpret_cast<void*>(va_page), prot_len, old, &tmp);
    if (!ok) {
      plan->notes.push_back("写入失败 @" + p.name + ": " + err);
      continue;
    }
    FlushInstructionCache(process, reinterpret_cast<void*>(p.va), len);
    ++wrote;
  }
  plan->notes.push_back("anti-crash 写入 " + std::to_string(wrote) + "/" +
                        std::to_string(plan->patches.size()) + " 条");
  return wrote == plan->patches.size();
}

}  // namespace win
}  // namespace wowmod
#endif
