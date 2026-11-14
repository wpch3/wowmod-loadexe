// FileDataID loose-file hook 安装实现。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/fd_hook.hpp"

#include "wowmod/intercept_stub.hpp"

#include <cstdio>

#include <algorithm>
#include <cstring>

#include "windows/detour.hpp"
#include "wowmod/util.hpp"
#include "wowmod/x64_decode.hpp"

namespace wowmod {
namespace win {

namespace {

void step(InstallReport* r, const std::string& s) {
  if (r) r->steps.push_back(s);
}

}  // namespace

bool write_remote_string_table(HANDLE process,
                               const std::vector<std::pair<uint64_t, std::string>>& entries,
                               RemoteBlock* table_out, RemoteBlock* strings_out,
                               std::string* err) {
  std::vector<uint8_t> blob;
  std::vector<std::pair<int, uint32_t>> offsets;
  std::vector<uint8_t> table = serialize_id_table(entries, &blob, &offsets);
  if (table.empty()) {
    if (err) *err = "映射表为空";
    return false;
  }

  RemoteBlock strings(process, blob.size() ? blob.size() : 1, PAGE_READWRITE);
  if (!strings.ok()) {
    if (err) *err = "VirtualAllocEx(字符串块) 失败, GetLastError=" + std::to_string(GetLastError());
    return false;
  }
  if (!write_remote(process, reinterpret_cast<uint64_t>(strings.addr()), blob.data(), blob.size(),
                    err, false)) {
    return false;
  }

  // 把表项里的「blob 内偏移」改写成目标进程内的绝对地址
  const uint64_t strings_va = reinterpret_cast<uint64_t>(strings.addr());
  for (size_t i = 0; i < entries.size(); ++i) {
    uint32_t off = 0;
    std::memcpy(&off, table.data() + i * FileIdEntryLayout::kStride + FileIdEntryLayout::kPathOffset,
                sizeof(off));
    const uint64_t abs = strings_va + off;
    std::memcpy(table.data() + i * FileIdEntryLayout::kStride + FileIdEntryLayout::kPathOffset, &abs,
                sizeof(abs));
  }

  RemoteBlock table_block(process, table.size(), PAGE_READWRITE);
  if (!table_block.ok()) {
    if (err) *err = "VirtualAllocEx(id 表) 失败, GetLastError=" + std::to_string(GetLastError());
    return false;
  }
  if (!write_remote(process, reinterpret_cast<uint64_t>(table_block.addr()), table.data(),
                    table.size(), err, false)) {
    return false;
  }
  // 写入完成后收紧为只读（避免客户端/其他插件误改）
  DWORD old = 0;
  VirtualProtectEx(process, strings.addr(), strings.size(), PAGE_READONLY, &old);
  VirtualProtectEx(process, table_block.addr(), table_block.size(), PAGE_READONLY, &old);

  if (table_out) *table_out = std::move(table_block);
  if (strings_out) *strings_out = std::move(strings);
  return true;
}

bool FileIdHook::install(HANDLE process, const InstallRequest& req, InstallReport* out) {
  process_ = process;
  report_ = InstallReport{};
  if (out) *out = report_;
  auto fail = [&](const std::string& why) {
    report_.error = why;
    if (out) *out = report_;
    // 回滚
    if (detour_.installed) remove_detour(process_, &detour_, nullptr);
    id_table_.release();
    strings_.release();
    stub_.release();
    return false;
  };

  if (!process) return fail("无效的进程句柄");
  if (req.hook_target == 0) return fail("未指定 hook 目标地址");
  if (req.entries.empty()) return fail("没有可用的 FileDataID 映射（files 目录为空或路径都不在 listfile 里）");

  // 1) 写表
  std::string err;
  if (!write_remote_string_table(process, req.entries, &id_table_, &strings_, &err)) {
    return fail("写入映射表失败: " + err);
  }
  report_.entry_count = req.entries.size();
  report_.id_table_va = reinterpret_cast<uint64_t>(id_table_.addr());
  report_.string_blob_va = reinterpret_cast<uint64_t>(strings_.addr());
  step(&report_, "映射表写入完成: " + std::to_string(req.entries.size()) + " 项, id 表 @" +
                     to_hex(report_.id_table_va, 16));

  // 2) 先探测 hook 点能否安全搬运（在写入任何跳转之前）
  {
    std::vector<uint8_t> window(64, 0);
    if (!read_remote(process, req.hook_target, window.data(), window.size(), &err)) {
      return fail("读取 hook 点失败: " + err);
    }
    const size_t copy_len = x64::find_safe_split(window.data(), window.size(), 0, req.min_cover);
    if (copy_len == 0) {
      return fail("hook 点不是完整指令边界（换一个 rva，或先用 wowmod analyze 的 site 结果）");
    }
    report_.copy_len = copy_len;
    step(&report_, "hook 点可搬运 " + std::to_string(copy_len) + " 字节完整指令");

    // 3) 生成跳板，但先确认 trampoline 地址后再回填
    //    这里先申请 trampoline（detour 内部会再申请，所以用同一套逻辑会重复；
    //    为保证跳板里写的是正确的 trampoline 地址，我们直接在这里做完整布置）
  }

  // 4) 生成 stub（此时还不知道 trampoline 地址，先留 0，稍后由 detour 提供）
  StubConfig sc;
  sc.id_register = req.id_register;
  sc.return_register = req.return_register;
  auto stub = build_fileid_stub(sc, report_.id_table_va,
                                static_cast<uint32_t>(req.entries.size()));
  if (!stub.ok()) {
    std::string why = "生成跳板失败:";
    for (const auto& e : stub.errors) why += "\n  " + e;
    return fail(why);
  }
  step(&report_, "跳板代码生成完成: " + std::to_string(stub.code.size()) + " 字节, id 寄存器=" +
                     req.id_register + ", 返回寄存器=" + req.return_register);

  // 5) 把跳板写进目标进程（先占位）
  if (!write_remote_code(process, stub.code, &stub_, &err)) {
    return fail("写入跳板失败: " + err);
  }
  report_.stub_va = reinterpret_cast<uint64_t>(stub_.addr());

  // 6) 安装 detour 指向跳板
  if (!install_detour(process, req.hook_target, report_.stub_va, req.min_cover, &detour_, &err)) {
    return fail("安装 detour 失败: " + err);
  }
  report_.trampoline_va = reinterpret_cast<uint64_t>(detour_.trampoline.addr());
  step(&report_, "detour 已安装: " + to_hex(req.hook_target, 16) + " -> " +
                     to_hex(report_.stub_va, 16) + ", trampoline @" +
                     to_hex(report_.trampoline_va, 16));

  // 7) 回填跳板里的两个绝对地址（trampoline 与 id 表已在前面填好 id 表）
  {
    std::vector<uint8_t> patched = stub.code;
    for (const auto& slot : stub.patch_slots) {
      uint64_t value = 0;
      if (slot.second == "id_table_va") value = report_.id_table_va;
      else if (slot.second == "trampoline_va") value = report_.trampoline_va;
      else {
        return fail("跳板里出现未知的回填项: " + slot.second);
      }
      if (slot.first + 8 > static_cast<int>(patched.size())) return fail("回填位置越界");
      std::memcpy(patched.data() + slot.first, &value, 8);
    }
    if (!write_remote(process, report_.stub_va, patched.data(), patched.size(), &err)) {
      return fail("回填跳板地址失败: " + err);
    }
    // 收紧跳板页保护
    DWORD old = 0;
    VirtualProtectEx(process, stub_.addr(), stub_.size(), PAGE_EXECUTE_READ, &old);
  }
  step(&report_, "跳板回填完成（trampoline + id 表）");

  report_.installed = true;
  if (out) *out = report_;
  return true;
}

std::vector<uint8_t> build_intercept_stub(uint64_t counter_va, uint64_t ring_va,
                                         uint32_t ring_mask) {
  return build_intercept_stub_bytes(counter_va, ring_va, ring_mask);
}

bool install_interceptors(HANDLE process, const std::vector<InterceptTarget>& targets,
                          const std::string& log_path, uint64_t counter_va, uint64_t ring_va,
                          uint32_t ring_count, std::vector<Detour>* out_detours,
                          std::vector<RemoteBlock>* out_stubs, std::string* err,
                          bool dry_run) {
  if (!process || targets.empty()) {
    if (err) *err = "没有要拦截的目标";
    return false;
  }
  if (ring_count < 2 || (ring_count & (ring_count - 1)) != 0) {
    if (err) *err = "ring_count 必须是 2 的幂且 >= 2";
    return false;
  }
  // 动手前先查每个目标的页状态：能不能改保护、跨不跨页。
  // 这一步只读，失败时能给出明确原因（而不是一句 GetLastError=87）。
  for (const auto& t : targets) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(t.target), &mbi, sizeof(mbi)) == 0) {
      if (err) {
        char b[192];
        std::snprintf(b, sizeof(b), "VirtualQueryEx(0x%llx) 失败, GetLastError=%lu",
                      static_cast<unsigned long long>(t.target), GetLastError());
        *err = b;
      }
      return false;
    }
    if (mbi.State != MEM_COMMIT) {
      if (err) {
        char b[192];
        std::snprintf(b, sizeof(b), "目标 0x%llx 未提交（State=0x%lx）",
                      static_cast<unsigned long long>(t.target),
                      static_cast<unsigned long>(mbi.State));
        *err = b;
      }
      return false;
    }
  }

  // 每个目标一条独立跳板（计数器/缓冲共享）
  for (const auto& t : targets) {
    std::vector<uint8_t> stub = build_intercept_stub(counter_va, ring_va, ring_count - 1);
    RemoteBlock stub_blk;
    if (!write_remote_code(process, stub, &stub_blk, err)) return false;
    Detour d;
    if (!install_detour(process, t.target, reinterpret_cast<uint64_t>(stub_blk.addr()), 14, &d, err,
                        dry_run))
      return false;
    // 回填 trampoline 地址
    std::vector<uint8_t> patched = stub;
    const uint64_t tramp = reinterpret_cast<uint64_t>(d.trampoline.addr());
    std::memcpy(patched.data() + patched.size() - 8, &tramp, 8);
    if (!write_remote(process, reinterpret_cast<uint64_t>(stub_blk.addr()), patched.data(),
                      patched.size(), err)) {
      return false;
    }
    if (out_detours) out_detours->push_back(std::move(d));
    if (out_stubs) out_stubs->push_back(std::move(stub_blk));
  }
  // 记录文件先建好，方便用户随时查看
  {
    std::wstring w = utf8_to_wide(to_native_path(log_path));
    HANDLE h = CreateFileW(w.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
  }
  return true;
}

namespace {
// 固定的全局槽位表：不做堆分配，异常路径上也能安全遍历。
struct InstalledSlot {
  HANDLE process;
  uint64_t target;
  uint8_t original[32];
  size_t len;
  volatile LONG live;
};
InstalledSlot g_slots[16];
}  // namespace

void register_installed_detour(const Detour* d) {
  if (!d || !d->installed) return;
  for (auto& s : g_slots) {
    if (InterlockedCompareExchange(&s.live, 0, 0) != 0) continue;
    const size_t n = d->original.size() < sizeof(s.original) ? d->original.size() : sizeof(s.original);
    std::memcpy(s.original, d->original.data(), n);
    s.len = n;
    s.target = d->target;
    s.process = nullptr;   // 由调用方设置
    InterlockedExchange(&s.live, 1);
    return;
  }
}

void emergency_remove_all(HANDLE process) {
  for (auto& s : g_slots) {
    if (InterlockedCompareExchange(&s.live, 0, 0) == 0) continue;
    if (s.len == 0 || s.target == 0) continue;
    HANDLE p = s.process ? s.process : process;
    if (!p) continue;
    // 逐页写回原始字节（同 write_remote 的保护处理）
    write_remote(p, s.target, s.original, s.len, nullptr, true);
    InterlockedExchange(&s.live, 0);
  }
}

void remove_interceptors(HANDLE process, std::vector<Detour>* detours,
                         std::vector<RemoteBlock>* stubs) {
  if (detours)
    for (auto& d : *detours) remove_detour(process, &d, nullptr);
  if (detours) detours->clear();
  if (stubs) stubs->clear();
}

bool FileIdHook::remove() {
  bool ok = true;
  if (detour_.installed) ok = remove_detour(process_, &detour_, nullptr);
  stub_.release();
  id_table_.release();
  strings_.release();
  report_.installed = false;
  return ok;
}

}  // namespace win
}  // namespace wowmod
#endif
