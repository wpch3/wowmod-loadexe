// Arctium 的 anti-crash 机制（PrepareAntiCrash）的 Windows 侧。
//
// 为什么必须有它 —— 这是「补丁装上了但客户端崩」的唯一原因：
//
//   客户端把映像映射成 section，并在运行时反复核对
//     (a) 代码页的字节是否还是它映射进去的样子（完整性校验）
//     (b) 映射基址/视图是否被换掉（remap 校验）
//   任何一处被改，校验函数以 EXCEPTION_INTERNAL_ERROR (0xC00000E5) 结束进程，
//   崩溃栈落在 ntdll!RtlReportCriticalFailure —— 不是客户端代码。
//   用户实测的崩溃就是这个，且 RIP 与第一次一字不差。
//
// Arctium 的解法（src/Launcher.cs PrepareAntiCrash + Patches/Windows.cs）：
//
//   1. 完整性校验函数：特征码 Integrity / Integrity2 命中处写 C2 00 00
//      = `ret 0`。整个校验函数直接返回 0（"没有发现篡改"）。
//
//   2. Remap 校验：特征码 Remap 命中处（48 ?? ?? 1E 0F 83），读出紧随其后的
//      跳转指令，算出它真正要去的地址 jumpToValue；然后全映像搜索
//      「跳转目标正好是 jumpToValue」的跳转，把它们统一改成
//      「往前挪 1 字节」的同目标跳转：
//          E9 rel32 (5 字节)  ->  E9 (rel32+1)    （仍然 5 字节）
//          EB rel8  (2 字节)  ->  EB              （1 字节，且要求前 3 字节是 0x48）
//      效果是那些 remap 校验里「拿真实代码和映像比对」的跳转全部错位，
//      校验拿不到真实代码，于是不会判定被 remap。
//
// 这两个都是【数据补丁】，没有 hook、没有跳板、没有指令搬运，
// 所以在被冻结的线程上写入是安全的。纯逻辑在 core/anticrash_plan.cpp。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <string>

#include "wowmod/anticrash_plan.hpp"

namespace wowmod {
namespace win {

// 读主映像、调用纯逻辑算出补丁计划。只读，不写。
//
// cert_patches: 是否同时算证书补丁（连私有服务器才需要）。默认 false。
AntiCrashPlan plan_anti_crash(HANDLE process, bool cert_patches = false);

// 写入计划里的补丁。返回是否全部成功。
bool apply_anti_crash(HANDLE process, AntiCrashPlan* plan);

// ---- Arctium WinMemory.RemapAndPatch 的移植（此前完全缺失的一步）----
//
// 上游原文（src/IO/WinMemory.cs:217-285）：
//   NtSuspendProcess
//   Data = Read(BaseAddress, RegionSize)          // 整块模块快照
//   NtCreateSection(maxSize=RegionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT)
//   NtUnmapViewOfSection(process, BaseAddress)    // 卸掉原来的视图
//   NtMapViewOfSection(... PAGE_EXECUTE_READ)     // 用新 section 重新映射成 RX
//   ApplyPatches(true)                            // 补丁打在【本地快照】上
//   NtMapViewOfSection(... PAGE_READWRITE)        // 再开一个可写视图
//   WriteProcessMemory(可写视图, Data, viewSize)  // 整块写穿透到 section
//   NtUnmapViewOfSection(可写视图)                // 卸掉可写视图
//   NtResumeProcess
//
// 为什么必须这么做，而不是直接在原页上 WriteProcessMemory：
//   * 原视图是壳自己映射的，页属性可疑（实测 Protect=0x04 RW）；
//     在上面写的字节会被完整性校验读到，判定为篡改 -> 0xC00000E5。
//   * 换成我们自己创建的 section 后，我们写的是【这个 section 的内容】。
//     客户端读到的就是"它本来该有的样子"，校验通过。
//
// patches: 已按 VA 排序、且 VA 都在 [base, base+size) 内的字节补丁。
// 返回 false 时进程一定已被恢复（不会留下挂起）。
bool remap_and_patch(HANDLE process, uint64_t base, uint64_t size,
                     const std::vector<AntiCrashPatch>& patches, std::string* err = nullptr,
                     bool caller_already_suspended = false);

}  // namespace win
}  // namespace wowmod
#endif
