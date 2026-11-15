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
    DWORD mbi_prev_protect = 0;
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
      mbi_prev_protect = mbi.Protect;
      plan->notes.push_back("  " + p.name + ": 页 0x" + to_hex(va_page, 16) +
                           " State=committed Type=0x" + to_hex(mbi.Type, 8) +
                           " Protect=0x" + to_hex(mbi.Protect, 8));
    }

    // 【失败原因：我一直在请求 PAGE_EXECUTE_READWRITE】
    //
    // 线上日志：
    //   jmp_rel32@110286715: 页 0x692d000 Type=0x40000(MEM_MAPPED) Protect=0x04(READWRITE)
    //   VirtualProtectEx ... 长度 4096 -> GetLastError=87
    //
    // 这页【本来就是 READWRITE】。我却在请求 EXECUTE_READWRITE。
    // 对一个 MEM_MAPPED 的只读/可写数据视图，内核按 section 属性
    // 拒绝追加 EXECUTE —— 返回就是 87。
    //
    // 而写这几个字节根本不需要 EXECUTE：写入只需要可写。
    // 执行权限由客户端自己的执行视图负责（这是壳的双视图结构）。
    //
    // 所以按协议降级：先试 EXECUTE_READWRITE（正常代码页），
    // 失败就只请求 READWRITE；本来就可写则完全不改保护。
    const bool already_writable = (mbi_prev_protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                                                      PAGE_EXECUTE_READWRITE |
                                                      PAGE_EXECUTE_WRITECOPY)) != 0;
    bool protect_ok = already_writable;
    std::string how;
    if (already_writable) {
      how = "页本就可写，未改保护";
      old = mbi_prev_protect;
    } else if (VirtualProtectEx(process, reinterpret_cast<void*>(va_page), prot_len,
                                PAGE_EXECUTE_READWRITE, &old)) {
      how = "PAGE_EXECUTE_READWRITE";
      protect_ok = true;
    } else {
      const DWORD e1 = GetLastError();
      if (VirtualProtectEx(process, reinterpret_cast<void*>(va_page), prot_len,
                           PAGE_READWRITE, &old)) {
        how = "PAGE_EXECUTE_READWRITE 被拒(err=" + std::to_string(e1) +
              ")，降级 PAGE_READWRITE 成功";
        protect_ok = true;
      } else {
        plan->notes.push_back("VirtualProtectEx 失败 @" + p.name + " (va=0x" +
                             to_hex(p.va, 16) + ", 页 0x" + to_hex(va_page, 16) +
                             ", 长度 " + std::to_string(prot_len) +
                             "): EXECUTE_READWRITE err=" + std::to_string(e1) +
                             ", READWRITE err=" + std::to_string(GetLastError()));
      }
    }
    if (!protect_ok) continue;
    plan->notes.push_back("  " + p.name + ": " + how);

    const bool ok = write_remote(process, p.va, p.bytes.data(), len, &err);
    if (!already_writable) {
      DWORD tmp = 0;
      VirtualProtectEx(process, reinterpret_cast<void*>(va_page), prot_len, old, &tmp);
    }
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


// ============================================================================
// Arctium WinMemory.RemapAndPatch 的移植。
//
// 这是此前【完全缺失】的一步 —— 代码里只有注释提到它，从未实现过。
// 缺了它的直接后果：所有补丁都写在壳自己映射的原视图上（实测
// Protect=0x04 PAGE_READWRITE），客户端的完整性校验读到被改的字节，
// 判定为篡改，以 EXCEPTION_INTERNAL_ERROR (0xC00000E5) 结束进程。
// 这就是用户截图那个崩溃，也是"补丁装上了但一进游戏就崩"的根因。
// ============================================================================
namespace {

// NTSTATUS 成功码
constexpr LONG kStatusSuccess = 0;

using NtCreateSectionFn = LONG(WINAPI*)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG,
                                        HANDLE);
using NtMapViewOfSectionFn = LONG(WINAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
                                           PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
using NtUnmapViewOfSectionFn = LONG(WINAPI*)(HANDLE, PVOID);
using NtSuspendProcessFn = LONG(WINAPI*)(HANDLE);
using NtResumeProcessFn = LONG(WINAPI*)(HANDLE);

struct NtProcs {
  NtCreateSectionFn create = nullptr;
  NtMapViewOfSectionFn map = nullptr;
  NtUnmapViewOfSectionFn unmap = nullptr;
  NtSuspendProcessFn suspend = nullptr;
  NtResumeProcessFn resume = nullptr;
  bool ok() const { return create && map && unmap && suspend && resume; }
};

NtProcs load_nt() {
  NtProcs p;
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) return p;
  p.create = reinterpret_cast<NtCreateSectionFn>(GetProcAddress(ntdll, "NtCreateSection"));
  p.map = reinterpret_cast<NtMapViewOfSectionFn>(GetProcAddress(ntdll, "NtMapViewOfSection"));
  p.unmap = reinterpret_cast<NtUnmapViewOfSectionFn>(GetProcAddress(ntdll, "NtUnmapViewOfSection"));
  p.suspend = reinterpret_cast<NtSuspendProcessFn>(GetProcAddress(ntdll, "NtSuspendProcess"));
  p.resume = reinterpret_cast<NtResumeProcessFn>(GetProcAddress(ntdll, "NtResumeProcess"));
  return p;
}

}  // namespace

bool remap_and_patch(HANDLE process, uint64_t base, uint64_t size,
                     const std::vector<AntiCrashPatch>& patches, std::string* err,
                     bool caller_already_suspended) {
  auto fail = [&](const std::string& m) {
    if (err) *err = m;
    return false;
  };

  if (!process || base == 0 || size < 0x1000) {
    return fail("remap_and_patch 参数无效（base/size）");
  }

  const NtProcs nt = load_nt();
  if (!nt.ok()) return fail("ntdll 缺少 NtCreateSection/NtMapViewOfSection/NtUnmapViewOfSection");

  // ---- 1. 挂起 ----
  //
  // 上游 RemapAndPatch 第一句就是 NtSuspendProcess。但我们的调用方
  // （mod_loader）在进入这一步之前【已经】挂起过整个进程了。
  // NtSuspendProcess 不是幂等的：嵌套调用会让挂起计数 +1，
  // 之后一次 resume 只减回 1，进程仍然挂着 —— 客户端永久冻死。
  // 所以由调用方说明"已经挂起了"，我们就不要再挂/恢复。
  const bool we_own_suspend = !caller_already_suspended;
  if (we_own_suspend) nt.suspend(process);

  struct ResumeOnExit {
    NtResumeProcessFn fn;
    HANDLE p;
    bool active;
    ~ResumeOnExit() {
      if (active && fn && p) fn(p);
    }
  } resume_guard{nt.resume, process, we_own_suspend};

  // ---- 2. 整块快照（上游: Data = Read(viewAddress, viewSize)）----
  std::vector<uint8_t> data(static_cast<size_t>(size), 0);
  // 记录哪些页真的读到了内容。重映射后这些页会被快照整体覆盖，
  // 没读到的页会变成 0 —— 那就等于把客户端代码抹掉，必崩。
  // 所以只要有「应该读却没读到」的页，就拒绝重映射。
  std::vector<uint8_t> page_filled((static_cast<size_t>(size) + 0xFFF) / 0x1000, 0);
  {
    SIZE_T got = 0;
    if (ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base), data.data(),
                          static_cast<SIZE_T>(data.size()), &got) &&
        got == data.size()) {
      std::fill(page_filled.begin(), page_filled.end(), 1);
    } else {
      // 整块读经常因为中间有空洞而失败；退化成逐段读，能读多少读多少。
      // Arctium 在这种情况下直接报"Error while creating the view backup"，
      // 我们至少把可读部分拿到，并如实记录。
      size_t filled = 0;
      uint64_t off = 0;
      while (off < size) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(process, reinterpret_cast<LPCVOID>(base + off), &mbi, sizeof(mbi)))
          break;
        if (mbi.State == MEM_COMMIT) {
          const uint64_t avail = std::min<uint64_t>(
              static_cast<uint64_t>(mbi.RegionSize) - ((base + off) -
                                                       reinterpret_cast<uint64_t>(mbi.BaseAddress)),
              size - off);
          SIZE_T g2 = 0;
          if (ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base + off), data.data() + off,
                                static_cast<SIZE_T>(avail), &g2) &&
              g2 > 0) {
            filled += g2;
            for (uint64_t pg = off / 0x1000; pg * 0x1000 < off + g2 && pg < page_filled.size();
                 ++pg) {
              // 只有整页都读到了才算填充 —— 半页同样是空洞
              const uint64_t pg_begin = pg * 0x1000;
              if (pg_begin >= off && pg_begin + 0x1000 <= off + g2) page_filled[pg] = 1;
            }
          }
        }
        const uint64_t next =
            reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= base + off) break;
        off = next - base;
      }
      if (filled == 0) return fail("无法读取映像快照（整块与逐段都失败）");
    }
  }

  // ---- 3. 把补丁打在【本地快照】上（上游 ApplyPatches(remap: true)）----
  //   这才是关键：我们改的是"准备写进去的内容"，而不是进程里已映射的页。
  // 调用共享的纯函数（有单测覆盖），而不是在这里另写一份。
  const size_t applied = apply_patches_to_snapshot(&data, base, patches);
  if (applied < patches.size()) {
    // 有补丁落不进快照 —— 说明规划用的 VA 与实际映射范围不一致。
    // 不静默继续：少写一条 anti-crash 就可能被校验抓到。
    return fail("有 " + std::to_string(patches.size() - applied) + "/" +
                std::to_string(patches.size()) + " 条补丁落在快照之外（基址 0x" +
                to_hex(base, 16) + "，区域 " + std::to_string(size) + " 字节）");
  }

  // ---- 3a2. 补丁地址必须都在重映射区间内 ----
  //
  // 重映射会把这个区间整体替换成我们的快照内容。若某条补丁的 VA 落在
  // 区间外，写进去也不会生效；更糟的是它会被误认为"已写入"。
  for (const auto& p : patches) {
    if (p.va < base || p.va + p.bytes.size() > base + size) {
      return fail("补丁 " + p.name + " @0x" + to_hex(p.va, 16) +
                  " 不在重映射区间 [0x" + to_hex(base, 16) + ", 0x" + to_hex(base + size, 16) +
                  ") 内 —— 拒绝重映射（写入不会生效）");
    }
  }

  // ---- 3b. 空洞检查（在不可逆的 unmap 之前）----
  //
  // 只要有已提交、可读、却没有被快照完整覆盖的页，重映射就会把它写成 0。
  // 那种情况下【必须放弃重映射】并告诉调用方回退到直接写入 ——
  // 宁可只改几个字节被校验抓到，也不能把整个函数抹成 0。
  {
    size_t holes = 0;
    uint64_t first_hole = 0;
    for (uint64_t off = 0; off < size; off += 0x1000) {
      const size_t pg = static_cast<size_t>(off / 0x1000);
      if (pg >= page_filled.size() || page_filled[pg]) continue;
      MEMORY_BASIC_INFORMATION mbi{};
      if (!VirtualQueryEx(process, reinterpret_cast<LPCVOID>(base + off), &mbi, sizeof(mbi)))
        continue;
      if (mbi.State != MEM_COMMIT) continue;          // 未提交页不在映像内容里
      if (mbi.Protect & PAGE_GUARD) continue;
      if ((mbi.Protect & (PAGE_NOACCESS)) != 0) continue;
      if (!holes) first_hole = base + off;
      ++holes;
    }
    if (holes) {
      return fail("映像快照有 " + std::to_string(holes) + " 个已提交页没读到（首个 0x" +
                  to_hex(first_hole, 16) + "），重映射会把它们清零 —— 已放弃重映射");
    }
  }

  // ---- 4. 建 section（PAGE_EXECUTE_READWRITE + SEC_COMMIT）----
  HANDLE sect = nullptr;
  LARGE_INTEGER max_size{};
  max_size.QuadPart = static_cast<LONGLONG>(size);
  const ULONG kPageExecuteReadWrite = 0x40;
  const ULONG kSecCommit = 0x8000000;
  LONG st = nt.create(&sect, 0xF001F, nullptr, &max_size, kPageExecuteReadWrite, kSecCommit, nullptr);
  if (st != kStatusSuccess || !sect) {
    return fail("NtCreateSection 失败, NTSTATUS=0x" + to_hex(static_cast<uint32_t>(st), 8));
  }
  struct SectClose {
    HANDLE h;
    ~SectClose() {
      if (h) CloseHandle(h);
    }
  } sect_guard{sect};

  // ---- 5. 卸掉原视图，再用新 section 映射到同一个地址（大小不变）----
  //
  // 【为什么必须同址】：模块里的所有 RIP 相对寻址、IAT、异常表都假定
  // 映像在 base 上。换个地址就全崩。上游也是把 viewBase 固定成 viewAddress。
  st = nt.unmap(process, reinterpret_cast<PVOID>(base));
  if (st != kStatusSuccess) {
    return fail("NtUnmapViewOfSection 失败, NTSTATUS=0x" + to_hex(static_cast<uint32_t>(st), 8) +
                "（原视图未被卸下，进程未受影响）");
  }

  uint64_t view_base = base;
  LARGE_INTEGER off0{};
  SIZE_T view_size = 0;
  // ViewShare = 2（映射到相同地址需要 ImageMap 语义）
  st = nt.map(sect, process, reinterpret_cast<PVOID*>(&view_base), 0, static_cast<SIZE_T>(size),
              &off0, &view_size, 2, 0, PAGE_EXECUTE_READ);
  if (st != kStatusSuccess) {
    // 【这是不可恢复的状态】
    //
    // 原视图已经卸下，新视图映射失败 —— 进程此刻【没有】客户端模块。
    // 任何后续执行都会立刻崩。不能只是返回 false 让调用方"回退到逐条写"，
    // 因为逐条写需要的页已经不存在了。
    //
    // 尽力补救：再试一次映射（偶尔第一次会因地址被占用而失败），
    // 仍然失败就明确报告"进程已不可用，必须重启客户端"。
    uint64_t retry_base = base;
    LARGE_INTEGER off_r{};
    SIZE_T size_r = 0;
    st = nt.map(sect, process, reinterpret_cast<PVOID*>(&retry_base), 0,
                static_cast<SIZE_T>(size), &off_r, &size_r, 2, 0, PAGE_EXECUTE_READ);
    if (st != kStatusSuccess) {
      return fail("NtMapViewOfSection(RX) 失败且重试也失败, NTSTATUS=0x" +
                  to_hex(static_cast<uint32_t>(st), 8) +
                  " —— 原视图已卸下、新视图未建立，客户端模块已丢失。"
                  "进程不可再使用，必须结束客户端后重试。（这是单一失败点，"
                  "不会再自动回退）");
    }
    view_base = retry_base;
    view_size = size_r;
  }

  // ---- 6. 开第二个可写视图，整块写穿透 ----
  uint64_t rw_base = 0;
  LARGE_INTEGER off1{};
  SIZE_T rw_size = 0;
  st = nt.map(sect, process, reinterpret_cast<PVOID*>(&rw_base), 0, static_cast<SIZE_T>(size),
              &off1, &rw_size, 2, 0, PAGE_READWRITE);
  if (st != kStatusSuccess) {
    return fail("NtMapViewOfSection(RW) 失败, NTSTATUS=0x" + to_hex(static_cast<uint32_t>(st), 8));
  }

  SIZE_T wrote = 0;
  const BOOL wok = WriteProcessMemory(process, reinterpret_cast<LPVOID>(rw_base), data.data(),
                                      static_cast<SIZE_T>(data.size()), &wrote);
  nt.unmap(process, reinterpret_cast<PVOID>(rw_base));   // 可写视图用完立刻卸掉

  if (!wok || wrote != data.size()) {
    return fail("WriteProcessMemory(可写视图) 失败, 写入 " + std::to_string(wrote) + "/" +
                std::to_string(data.size()));
  }

  // ---- 7. 收尾：确认最终视图是 RX（上游同样检查 AllocationProtect）----
  MEMORY_BASIC_INFORMATION mbi{};
  if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(base), &mbi, sizeof(mbi)) != 0) {
    if (mbi.AllocationProtect != PAGE_EXECUTE_READ) {
      DWORD old = 0;
      VirtualProtectEx(process, reinterpret_cast<LPVOID>(base), static_cast<SIZE_T>(size),
                       PAGE_EXECUTE_READ, &old);
    }
  }
  FlushInstructionCache(process, reinterpret_cast<LPCVOID>(base), static_cast<SIZE_T>(size));

  if (err) {
    *err = "已重映射并在快照上应用 " + std::to_string(applied) + "/" +
           std::to_string(patches.size()) + " 条补丁，视图 0x" + to_hex(base, 16) + " size 0x" +
           to_hex(view_size, 16);
  }
  // resume_guard 析构时恢复进程
  return true;
}

}  // namespace win
}  // namespace wowmod
#endif
