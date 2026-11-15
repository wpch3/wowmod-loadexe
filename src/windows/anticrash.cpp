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
  // 用最大那块映像（= PEB 基址上的整幅映像）来规划：Arctium 也是在自己的
  // memory.Data 上找。
  AntiCrashPlan plan;
  const auto images = scan_process_images(process);
  if (images.empty()) {
    plan.error = "扫不到任何映像";
    return plan;
  }
  const ScannedImage* main_img = &images[0];
  for (const auto& img : images)
    if (img.size > main_img->size) main_img = &img;
  if (main_img->bytes.size() < 0x1000) {
    plan.error = "主映像内容为空（不可读）";
    return plan;
  }
  plan = plan_anti_crash_from_image(main_img->bytes, main_img->base, cert_patches);
  plan.notes.push_back("规划基于映像 0x" + to_hex(main_img->base, 16) + " （" +
                       std::to_string(main_img->bytes.size() / 1048576) + " MB）");
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
