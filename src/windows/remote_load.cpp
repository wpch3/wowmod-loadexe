// 远程加载实现。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/remote_load.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <string>

#include "wowmod/launcher_stub.hpp"
#include "wowmod/util.hpp"

namespace wowmod {
namespace win {

namespace {

std::string describe_win_error(uint32_t code) {
  switch (code) {
    case 0:    return "（无错误）";
    case 2:    return "ERROR_FILE_NOT_FOUND：路径不存在";
    case 3:    return "ERROR_PATH_NOT_FOUND：目录不存在";
    case 5:    return "ERROR_ACCESS_DENIED：权限不足";
    case 126:  return "ERROR_MOD_NOT_FOUND：DLL 自身依赖的某个模块找不到";
    case 127:  return "ERROR_PROC_NOT_FOUND：DLL 需要的导出找不到";
    case 193:  return "ERROR_BAD_EXE_FORMAT：位数或格式不对（32/64 位不匹配）";
    case 998:  return "ERROR_NOACCESS：写入的内存不可访问";
    case 1114: return "ERROR_DLL_INIT_FAILED：DllMain 返回了 FALSE";
    case 577:  return "ERROR_INVALID_IMAGE_HASH：签名/完整性校验拒绝加载";
    case 87:   return "ERROR_INVALID_PARAMETER";
    default:   return "（未知错误码）";
  }
}

bool write_proc(HANDLE p, uint64_t addr, const void* src, size_t n) {
  DWORD old = 0;
  if (!VirtualProtectEx(p, reinterpret_cast<void*>(addr), n, PAGE_EXECUTE_READWRITE, &old))
    return false;
  SIZE_T w = 0;
  const bool ok = WriteProcessMemory(p, reinterpret_cast<void*>(addr), src, n, &w) && w == n;
  return ok;
}

bool read_proc(HANDLE p, uint64_t addr, void* dst, size_t n) {
  SIZE_T got = 0;
  return ReadProcessMemory(p, reinterpret_cast<const void*>(addr), dst, n, &got) && got == n;
}

// 执行一块已写好的远程代码，并取回 rax/rdx
RemoteCallResult run_stub(HANDLE process, uint64_t stub, DWORD timeout_ms) {
  RemoteCallResult r;
  HANDLE t = CreateRemoteThread(process, nullptr, 0,
                                reinterpret_cast<LPTHREAD_START_ROUTINE>(stub), nullptr, 0,
                                nullptr);
  if (!t) return r;
  const DWORD w = WaitForSingleObject(t, timeout_ms);
  if (w != WAIT_OBJECT_0) {
    r.ran = true;
    r.timed_out = true;
    CloseHandle(t);
    return r;
  }
  DWORD code = 0;
  GetExitCodeThread(t, &code);
  CloseHandle(t);
  r.ran = true;
  r.r0 = code;
  return r;
}

// 在【同一个线程】里调用 fn(a0) 然后 GetLastError()，两个结果都写回。
// 关键：GetLastError 是 per-thread 的。之前用两次独立的 CreateRemoteThread，
// 第二次是新线程，读到的一定是 0 —— 于是错误码永远是"（无错误）"。
std::vector<uint8_t> build_load_and_error_stub(uint64_t load_library, uint64_t get_last_error,
                                               uint64_t path_va, uint64_t out_module,
                                               uint64_t out_error) {
  std::vector<uint8_t> c;
  auto db = [&](std::initializer_list<uint8_t> bs) { c.insert(c.end(), bs.begin(), bs.end()); };
  auto dq = [&](uint64_t v) {
    const size_t at = c.size();
    c.resize(at + 8);
    std::memcpy(c.data() + at, &v, 8);
  };
  db({0x48, 0x83, 0xEC, 0x28});   // sub rsp, 0x28
  db({0x48, 0xB9}); dq(path_va);  // mov rcx, path
  db({0x48, 0xB8}); dq(load_library);
  db({0xFF, 0xD0});               // call rax  -> LoadLibraryW
  db({0x48, 0xB9}); dq(out_module);
  db({0x48, 0x89, 0x01});         // mov [rcx], rax
  db({0x48, 0xB8}); dq(get_last_error);
  db({0xFF, 0xD0});               // call rax  -> GetLastError（同一线程！）
  db({0x48, 0xB9}); dq(out_error);
  db({0x89, 0x01});               // mov [rcx], eax
  db({0x48, 0x83, 0xC4, 0x28});   // add rsp, 0x28
  db({0xC3});
  return c;
}

// 把 fn(a0,a1,a2) 包成一段壳代码：返回 rax 到某个内存槽、rdx 到另一个槽
std::vector<uint8_t> build_call_stub(uint64_t fn, uint64_t a0, uint64_t a1, uint64_t a2,
                                     uint64_t out_rax, uint64_t out_rdx) {
  std::vector<uint8_t> c;
  auto db = [&](std::initializer_list<uint8_t> bs) { c.insert(c.end(), bs.begin(), bs.end()); };
  auto dq = [&](uint64_t v) {
    const size_t at = c.size();
    c.resize(at + 8);
    std::memcpy(c.data() + at, &v, 8);
  };
  // 栈对齐：Windows x64 要求进入函数时 rsp%16==8（即调用点 rsp%16==0 之后 call 压入 8）
  // 新建线程的 rsp 是 16 对齐的，所以先 sub 0x28 再 call（保证 call 时 rsp%16==8）
  db({0x48, 0x83, 0xEC, 0x28});  // sub rsp, 0x28
  db({0x48, 0xB9}); dq(a0);      // mov rcx, a0
  db({0x48, 0xBA}); dq(a1);      // mov rdx, a1
  db({0x49, 0xB8}); dq(a2);      // mov r8,  a2
  db({0x48, 0xB8}); dq(fn);      // mov rax, fn
  db({0xFF, 0xD0});              // call rax
  db({0x48, 0xB9}); dq(out_rax); // mov rcx, out_rax
  db({0x48, 0x89, 0x01});        // mov [rcx], rax
  db({0x48, 0xB9}); dq(out_rdx); // mov rcx, out_rdx
  db({0x48, 0x89, 0x11});        // mov [rcx], rdx
  db({0x48, 0x83, 0xC4, 0x28});  // add rsp, 0x28
  db({0xC3});                    // ret
  return c;
}

bool write_remote_ex(HANDLE p, const std::vector<uint8_t>& code, uint64_t* out_va) {
  void* mem = VirtualAllocEx(p, nullptr, code.size(), MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
  if (!mem) return false;
  if (!write_proc(p, reinterpret_cast<uint64_t>(mem), code.data(), code.size())) {
    VirtualFreeEx(p, mem, 0, MEM_RELEASE);
    return false;
  }
  FlushInstructionCache(p, mem, code.size());
  *out_va = reinterpret_cast<uint64_t>(mem);
  return true;
}

void* alloc_rw(HANDLE p, size_t n) {
  return VirtualAllocEx(p, nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

}  // namespace

RemoteCallResult call_remote(HANDLE process, uint64_t fn, uint64_t arg0, uint64_t arg1,
                             uint64_t arg2, DWORD timeout_ms, std::string* err) {
  RemoteCallResult res;
  void* out = alloc_rw(process, 16);
  if (!out) {
    if (err) *err = "VirtualAllocEx(结果槽) 失败";
    return res;
  }
  const uint64_t out_va = reinterpret_cast<uint64_t>(out);
  const auto code =
      build_call_stub(fn, arg0, arg1, arg2, out_va, out_va + 8);
  uint64_t stub = 0;
  if (!write_remote_ex(process, code, &stub)) {
    if (err) *err = "写入调用壳失败";
    VirtualFreeEx(process, out, 0, MEM_RELEASE);
    return res;
  }
  HANDLE t = CreateRemoteThread(process, nullptr, 0,
                                reinterpret_cast<LPTHREAD_START_ROUTINE>(stub), nullptr, 0,
                                nullptr);
  if (!t) {
    if (err) *err = "CreateRemoteThread 失败, GetLastError=" + std::to_string(GetLastError());
    VirtualFreeEx(process, out, 0, MEM_RELEASE);
    VirtualFreeEx(process, reinterpret_cast<void*>(stub), 0, MEM_RELEASE);
    return res;
  }
  res.ran = true;
  const DWORD w = WaitForSingleObject(t, timeout_ms);
  if (w != WAIT_OBJECT_0) res.timed_out = true;
  CloseHandle(t);
  uint64_t r0 = 0, r1 = 0;
  read_proc(process, out_va, &r0, 8);
  read_proc(process, out_va + 8, &r1, 8);
  res.r0 = r0;
  res.r1 = r1;
  VirtualFreeEx(process, out, 0, MEM_RELEASE);
  VirtualFreeEx(process, reinterpret_cast<void*>(stub), 0, MEM_RELEASE);
  return res;
}

// ---------------------------------------------------------------- 路径 1
LoadAttempt load_by_remote_loadlibrary(HANDLE process, const std::string& dll_path) {
  LoadAttempt a;
  a.method = "CreateRemoteThread + LoadLibraryW";
  const std::wstring w = utf8_to_wide(to_native_path(dll_path));
  const size_t bytes = (w.size() + 1) * sizeof(wchar_t);
  void* remote = alloc_rw(process, bytes);
  if (!remote) {
    a.detail = "写入路径用的内存分配失败";
    return a;
  }
  if (!write_proc(process, reinterpret_cast<uint64_t>(remote), w.c_str(), bytes)) {
    a.detail = "WriteProcessMemory 路径失败";
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return a;
  }
  const HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  const uint64_t load_library =
      reinterpret_cast<uint64_t>(GetProcAddress(k32, "LoadLibraryW"));
  const uint64_t get_last_error =
      reinterpret_cast<uint64_t>(GetProcAddress(k32, "GetLastError"));

  void* out = alloc_rw(process, 16);
  uint64_t stub = 0;
  if (!out) {
    a.detail = "结果槽分配失败";
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return a;
  }
  const uint64_t out_va = reinterpret_cast<uint64_t>(out);
  const auto code = build_load_and_error_stub(load_library, get_last_error,
                                              reinterpret_cast<uint64_t>(remote), out_va,
                                              out_va + 8);
  if (!write_remote_ex(process, code, &stub)) {
    a.detail = "写入加载壳失败";
    VirtualFreeEx(process, out, 0, MEM_RELEASE);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return a;
  }
  const auto r = run_stub(process, stub, 60000);
  if (!r.ran) {
    a.detail = "CreateRemoteThread 失败, GetLastError=" + std::to_string(GetLastError());
    VirtualFreeEx(process, out, 0, MEM_RELEASE);
    VirtualFreeEx(process, reinterpret_cast<void*>(stub), 0, MEM_RELEASE);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return a;
  }
  if (r.timed_out) {
    a.detail = "远程线程 60 秒未返回（DllMain 卡住了）";
    VirtualFreeEx(process, out, 0, MEM_RELEASE);
    VirtualFreeEx(process, reinterpret_cast<void*>(stub), 0, MEM_RELEASE);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return a;
  }
  uint64_t mod = 0;
  uint32_t ecode = 0;
  read_proc(process, out_va, &mod, 8);
  read_proc(process, out_va + 8, &ecode, 4);
  VirtualFreeEx(process, out, 0, MEM_RELEASE);
  VirtualFreeEx(process, reinterpret_cast<void*>(stub), 0, MEM_RELEASE);
  VirtualFreeEx(process, remote, 0, MEM_RELEASE);

  a.module_base = mod;
  a.last_error = ecode;
  a.ok = mod != 0;
  if (a.ok) {
    a.detail = "已载入, 模块基址 0x" + to_hex(a.module_base, 16);
  } else {
    a.detail = "LoadLibraryW 返回 NULL, GetLastError=" + std::to_string(ecode) + " " +
               describe_win_error(ecode);
  }
  return a;
}

// ---------------------------------------------------------------- 路径 2
// 手工映射：不依赖目标进程的加载器，也不进模块表。
LoadAttempt load_by_manual_map(HANDLE process, const std::string& dll_path) {
  LoadAttempt a;
  a.method = "手工映射（不经系统加载器）";
  std::vector<uint8_t> file;
  if (!read_binary_file(dll_path, &file, nullptr)) {
    a.detail = "读不到我自己的 DLL 文件";
    return a;
  }
  const PeLayout pe = parse_pe_file(file);
  if (!pe.ok) {
    a.detail = "解析 PE 失败: " + pe.error;
    return a;
  }

  // 1) 在目标进程分配整块空间
  void* mem = VirtualAllocEx(process, nullptr, pe.size_of_image, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
  if (!mem) {
    a.detail = "VirtualAllocEx(" + std::to_string(pe.size_of_image) + ") 失败";
    return a;
  }
  const uint64_t base = reinterpret_cast<uint64_t>(mem);

  // 2) 按节摆放（内存布局：文件偏移 != RVA，所以逐节拷）
  std::vector<uint8_t> img(pe.size_of_image, 0);
  size_t hdr_end = 0x400;
  if (!pe.sections.empty()) hdr_end = pe.sections[0].raw_ptr;
  if (hdr_end > img.size()) hdr_end = img.size();
  std::memcpy(img.data(), file.data(), std::min(hdr_end, file.size()));
  for (const auto& s : pe.sections) {
    if (s.raw_size == 0 || s.va >= img.size()) continue;
    if (s.raw_ptr >= file.size()) continue;
    const size_t n = std::min<size_t>({static_cast<size_t>(s.raw_size),
                                       file.size() - s.raw_ptr,
                                       img.size() - s.va});
    std::memcpy(img.data() + s.va, file.data() + s.raw_ptr, n);
  }

  // 3) 重定位（只处理 DIR64，够用）
  const int64_t delta = static_cast<int64_t>(base) - static_cast<int64_t>(pe.image_base);
  if (delta != 0) {
    size_t applied = 0;
    for (const auto& r : pe.relocs) {
      if (r.type != 10) continue;
      if (static_cast<size_t>(r.rva) + 8 > img.size()) continue;
      uint64_t v = 0;
      std::memcpy(&v, img.data() + r.rva, 8);
      v = static_cast<uint64_t>(static_cast<int64_t>(v) + delta);
      std::memcpy(img.data() + r.rva, &v, 8);
      ++applied;
    }
    a.detail = "重定位 " + std::to_string(applied) + " 项; ";
  }

  // 4) 【必须先写入！】导入表解析要在目标进程里读 DLL 名字字符串，
  //    名字就在我们刚摆好的映像里。如果这时还没写入，远程 GetModuleHandleA
  //    读到的是全 0，会返回 NULL —— 于是每个模块都"缺失"、IAT 全是 0，
  //    入口点一执行就跳到地址 0（看起来"返回 0"，其实什么都没做）。
  //    这就是上一版 IAT 回填 0 项的直接原因。
  if (!write_proc(process, base, img.data(), img.size())) {
    a.detail += "写入映像失败(第一阶段)";
    VirtualFreeEx(process, mem, 0, MEM_RELEASE);
    return a;
  }
  FlushInstructionCache(process, mem, img.size());

  // 5) 解析导入表。
  //
  // 这里刻意【不】用远程 GetModuleHandleA/GetProcAddress，原因有两个：
  //   (a) 导入表里的 api-ms-win-crt-*.dll 是 **API set 虚拟名**，不是真实模块，
  //       GetModuleHandleA 对它们永远返回 NULL —— 这就是"缺 11 项"的根因。
  //   (b) 远程调用会被客户端可能存在的 hook 干扰。
  // 改成：在【本进程】里 GetProcAddress 拿到函数相对模块基址的 RVA，
  // 再用 Toolhelp 枚举【子进程】的真实模块基址，两者相加即得正确地址。
  // 同一个 DLL 在两进程里 ASLR 基址可能不同，但「函数 - 模块基址」的 RVA 恒定。
  size_t mapped_iat = 0;
  {
    const uint32_t imp_rva = [&]() -> uint32_t {
      if (file.size() < 0x40) return 0;
      const uint32_t lfanew = *reinterpret_cast<const uint32_t*>(file.data() + 0x3C);
      if (lfanew + 0x70 > file.size()) return 0;
      const uint16_t magic = *reinterpret_cast<const uint16_t*>(file.data() + lfanew + 24);
      const size_t dd = lfanew + 24 + (magic == 0x20B ? 112 : 96) + 1 * 8;
      if (dd + 4 > file.size()) return 0;
      return *reinterpret_cast<const uint32_t*>(file.data() + dd);
    }();

    if (imp_rva == 0) {
      a.detail += "没有导入表; ";
    } else {
      // 子进程模块快照
      struct ChildMod { uint64_t base; size_t size; };
      std::map<std::string, ChildMod> child;
      HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                             GetProcessId(process));
      if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me;
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
          do {
            std::string nm = wide_to_utf8(me.szModule);
            std::transform(nm.begin(), nm.end(), nm.begin(), ::tolower);
            child[nm] = {reinterpret_cast<uint64_t>(me.modBaseAddr), me.modBaseSize};
          } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
      }

      size_t patched = 0, missing = 0;
      std::string missing_names;
      uint32_t cursor = imp_rva;
      for (int guard = 0; guard < 256 && cursor + 20 <= img.size(); ++guard) {
        const uint8_t* d = img.data() + cursor;
        const uint32_t orig_thunk = *reinterpret_cast<const uint32_t*>(d);
        const uint32_t name_rva = *reinterpret_cast<const uint32_t*>(d + 12);
        const uint32_t first_thunk = *reinterpret_cast<const uint32_t*>(d + 16);
        if (name_rva == 0 || first_thunk == 0 || name_rva >= img.size()) break;

        std::string dll_name(reinterpret_cast<const char*>(img.data() + name_rva));
        // API set -> 真实承载模块。api-ms-win-crt-* 在 Win10+ 由 ucrtbase.dll 实现。
        std::string real = dll_name;
        std::string lower = dll_name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.rfind("api-ms-win-crt-", 0) == 0) real = "ucrtbase.dll";
        else if (lower.rfind("api-ms-win-core-", 0) == 0) real = "kernel32.dll";
        else if (lower.rfind("api-ms-win-", 0) == 0) {
          // 其它 API set：去掉前缀后无法可靠映射，标记缺失
          real = lower;
        }
        std::string real_lower = real;
        std::transform(real_lower.begin(), real_lower.end(), real_lower.begin(), ::tolower);

        HMODULE local_mod = GetModuleHandleW(utf8_to_wide(real).c_str());
        auto it = child.find(real_lower);
        if (!local_mod || it == child.end()) {
          ++missing;
          if (missing_names.size() < 200) missing_names += dll_name + " ";
          cursor += 20;
          continue;
        }
        const uint64_t local_base = reinterpret_cast<uint64_t>(local_mod);
        const uint64_t child_base = it->second.base;

        uint32_t t = orig_thunk ? orig_thunk : first_thunk;
        uint32_t slot = first_thunk;
        for (int k = 0; k < 8192 && t + 8 <= img.size() && slot + 8 <= img.size(); ++k) {
          const uint64_t oft = *reinterpret_cast<const uint64_t*>(img.data() + t);
          if (oft == 0) break;
          if (oft & 0x8000000000000000ull) {
            t += 8;
            slot += 8;
            continue;
          }
          uint64_t value = 0;
          if (oft + 2 < img.size()) {
            const char* fn_name = reinterpret_cast<const char*>(img.data() + oft + 2);
            FARPROC local_fn = GetProcAddress(local_mod, fn_name);
            if (local_fn) {
              const uint64_t rva = reinterpret_cast<uint64_t>(local_fn) - local_base;
              value = child_base + rva;
            } else {
              ++missing;
            }
          }
          if (value) {
            std::memcpy(img.data() + slot, &value, 8);
            ++patched;
          }
          t += 8;
          slot += 8;
        }
        cursor += 20;
      }
      mapped_iat = patched;
      a.detail += "IAT 回填 " + std::to_string(patched) + " 项";
      if (missing) a.detail += "（缺 " + std::to_string(missing) + " 项: " + missing_names + "）";
      a.detail += "; ";
    }
  }

  // 6) IAT 已经在 img 里改好，把整块再写一次（快照一致，避免只写部分节）
  if (!write_proc(process, base, img.data(), img.size())) {
    a.detail += "写入映像失败(IAT 回填阶段)";
    VirtualFreeEx(process, mem, 0, MEM_RELEASE);
    return a;
  }
  FlushInstructionCache(process, mem, img.size());
  {
    DWORD old = 0;
    VirtualProtectEx(process, mem, img.size(), PAGE_EXECUTE_READ, &old);
  }

  a.module_base = base;
  // 没有回填任何 IAT 就意味着所有 Win32 调用都是地址 0，
  // 入口点一执行就跳飞。这种"成功"比失败更危险，直接判失败。
  if (mapped_iat == 0) {
    a.detail += "映射到 0x" + to_hex(base, 16) + "，但 IAT 一项都没回填 —— 判定失败";
    a.ok = false;
    VirtualFreeEx(process, mem, 0, MEM_RELEASE);
    return a;
  }
  a.ok = true;
  a.detail += "映射到 0x" + to_hex(base, 16) + "（未进模块表，IAT " +
              std::to_string(mapped_iat) + " 项）";
  return a;
}

// ---------------------------------------------------------------- 路径 3
LoadAttempt load_by_nt_create_thread(HANDLE process, const std::string& dll_path) {
  LoadAttempt a;
  a.method = "NtCreateThreadEx + LoadLibraryW";
  using NtCreateThreadExFn = LONG(WINAPI*)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPVOID, LPVOID,
                                           ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);
  const auto nt = reinterpret_cast<NtCreateThreadExFn>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"));
  if (!nt) {
    a.detail = "拿不到 NtCreateThreadEx";
    return a;
  }
  const std::wstring w = utf8_to_wide(to_native_path(dll_path));
  const size_t bytes = (w.size() + 1) * sizeof(wchar_t);
  void* remote = alloc_rw(process, bytes);
  if (!remote) {
    a.detail = "路径内存分配失败";
    return a;
  }
  if (!write_proc(process, reinterpret_cast<uint64_t>(remote), w.c_str(), bytes)) {
    a.detail = "写路径失败";
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return a;
  }
  const uint64_t load_library = reinterpret_cast<uint64_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
  HANDLE thread = nullptr;
  const LONG st = nt(&thread, THREAD_ALL_ACCESS, nullptr, process,
                     reinterpret_cast<LPVOID>(load_library), remote, 0, 0, 0, 0, nullptr);
  if (st != 0 || !thread) {
    a.detail = "NtCreateThreadEx 失败, NTSTATUS=0x" + to_hex(static_cast<uint32_t>(st), 8);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return a;
  }
  WaitForSingleObject(thread, 60000);
  DWORD code = 0;
  GetExitCodeThread(thread, &code);
  CloseHandle(thread);
  a.module_base = code;
  a.ok = code != 0;
  a.detail = a.ok ? ("已载入, 0x" + to_hex(a.module_base, 16))
                  : ("线程退出码 0（LoadLibraryW 返回 NULL）");
  VirtualFreeEx(process, remote, 0, MEM_RELEASE);
  return a;
}

LoadAttempt load_runtime(HANDLE process, const std::string& dll_path,
                          std::vector<LoadAttempt>* attempts) {
  std::vector<LoadAttempt> all;
  all.push_back(load_by_remote_loadlibrary(process, dll_path));
  if (all.back().ok) {
    if (attempts) *attempts = all;
    return all.back();
  }
  all.push_back(load_by_nt_create_thread(process, dll_path));
  if (all.back().ok) {
    if (attempts) *attempts = all;
    return all.back();
  }
  all.push_back(load_by_manual_map(process, dll_path));
  if (attempts) *attempts = all;
  return all.back();
}

}  // namespace win
}  // namespace wowmod
#endif
