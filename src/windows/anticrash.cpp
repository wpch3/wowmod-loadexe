// Arctium PrepareAntiCrash 的 Windows 侧实现。见 anticrash.hpp。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/anticrash.hpp"

#include <cstdio>
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
  const ScannedImage* main_img = &images[0];
  for (const auto& img : images)
    if (img.size > main_img->size) main_img = &img;
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
    if (!VirtualProtectEx(process, reinterpret_cast<void*>(p.va), len,
                          PAGE_EXECUTE_READWRITE, &old)) {
      plan->notes.push_back("VirtualProtectEx 失败 @" + p.name + ": GetLastError=" +
                           std::to_string(GetLastError()));
      continue;
    }
    const bool ok = write_remote(process, p.va, p.bytes.data(), len, &err);
    DWORD tmp = 0;
    VirtualProtectEx(process, reinterpret_cast<void*>(p.va), len, old, &tmp);
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
