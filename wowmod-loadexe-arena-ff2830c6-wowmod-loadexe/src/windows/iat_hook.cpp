// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/iat_hook.hpp"

#include <tlhelp32.h>

#include <algorithm>
#include <cstring>
#include <type_traits>
#include <vector>

#include "windows/fs_hooks.hpp"
#include "windows/runtime.hpp"

namespace wowmod {
namespace win {

namespace {

OrigApi g_orig;
void* g_self = nullptr;

struct Replacement {
  const char* name;
  void* detour;
};

const char* kSystemDlls[] = {"kernel32.dll", "kernelbase.dll", "ntdll.dll"};

bool is_provider_dll(const char* name) {
  std::string n = to_lower(name ? name : "");
  for (const char* s : kSystemDlls) if (n == s) return true;
  // Win7+ 的 API Set 转发（api-ms-win-core-file-l1-1-0.dll 等）
  return starts_with(n, "api-ms-win-core-file") || starts_with(n, "api-ms-win-core-libraryloader") ||
         starts_with(n, "api-ms-win-core-synch");
}

void* resolve_original(const char* name) {
  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  HMODULE kb = GetModuleHandleW(L"kernelbase.dll");
  HMODULE ntd = GetModuleHandleW(L"ntdll.dll");
  std::wstring w = utf8_to_wide(name);
  if (auto p = GetProcAddress(k32, name)) return reinterpret_cast<void*>(p);
  if (kb) if (auto p = GetProcAddress(kb, name)) return reinterpret_cast<void*>(p);
  if (auto p = GetProcAddress(ntd, name)) return reinterpret_cast<void*>(p);
  (void)w;
  return nullptr;
}

void fill_originals() {
  auto set = [&](auto& dst, const char* name) {
    using Fn = std::remove_reference_t<decltype(dst)>;
    if (!dst) dst = reinterpret_cast<Fn>(resolve_original(name));
  };
  set(g_orig.CreateFileW, "CreateFileW");
  set(g_orig.CreateFileA, "CreateFileA");
  set(g_orig.GetFileAttributesW, "GetFileAttributesW");
  set(g_orig.GetFileAttributesA, "GetFileAttributesA");
  set(g_orig.GetFileAttributesExW, "GetFileAttributesExW");
  set(g_orig.FindFirstFileW, "FindFirstFileW");
  set(g_orig.FindFirstFileExW, "FindFirstFileExW");
  set(g_orig.FindNextFileW, "FindNextFileW");
  set(g_orig.FindClose, "FindClose");
  set(g_orig.LoadLibraryW, "LoadLibraryW");
  set(g_orig.LoadLibraryExW, "LoadLibraryExW");
  set(g_orig.NtCreateFile, "NtCreateFile");
  set(g_orig.NtOpenFile, "NtOpenFile");
}

std::vector<Replacement> replacements() {
  std::vector<Replacement> r;
  auto add = [&](const char* n, void* d) { r.push_back({n, d}); };
  add("CreateFileW", reinterpret_cast<void*>(DetourCreateFileW));
  add("CreateFileA", reinterpret_cast<void*>(DetourCreateFileA));
  add("GetFileAttributesW", reinterpret_cast<void*>(DetourGetFileAttributesW));
  add("GetFileAttributesA", reinterpret_cast<void*>(DetourGetFileAttributesA));
  add("GetFileAttributesExW", reinterpret_cast<void*>(DetourGetFileAttributesExW));
  add("FindFirstFileW", reinterpret_cast<void*>(DetourFindFirstFileW));
  add("FindFirstFileExW", reinterpret_cast<void*>(DetourFindFirstFileExW));
  add("FindNextFileW", reinterpret_cast<void*>(DetourFindNextFileW));
  add("FindClose", reinterpret_cast<void*>(DetourFindClose));
  add("LoadLibraryW", reinterpret_cast<void*>(DetourLoadLibraryW));
  add("LoadLibraryExW", reinterpret_cast<void*>(DetourLoadLibraryExW));
  add("NtCreateFile", reinterpret_cast<void*>(DetourNtCreateFile));
  add("NtOpenFile", reinterpret_cast<void*>(DetourNtOpenFile));
  return r;
}

// 返回被替换的 IAT 项数量
size_t patch_module_unsafe(HMODULE mod, const std::vector<Replacement>& reps) {
  if (!mod || mod == g_self) return 0;
  auto* base = reinterpret_cast<uint8_t*>(mod);
  {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    const auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dd.VirtualAddress || !dd.Size) return 0;
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dd.VirtualAddress);
    size_t count = 0;
    for (; desc->Name && desc->FirstThunk; ++desc) {
      const char* dll = reinterpret_cast<const char*>(base + desc->Name);
      if (!is_provider_dll(dll)) continue;
      // 没有 INT（OriginalFirstThunk）时 IAT 里已是地址，无法安全地按名字定位，跳过该描述符
      if (!desc->OriginalFirstThunk) continue;
      auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
      auto* first = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
      for (; first->u1.Ordinal && thunk->u1.Function; ++first, ++thunk) {
        if (first->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
        auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + first->u1.AddressOfData);
        const char* fn = reinterpret_cast<const char*>(ibn->Name);
        for (const auto& rep : reps) {
          if (std::strcmp(fn, rep.name) != 0) continue;
          DWORD old = 0;
          auto* slot = reinterpret_cast<uintptr_t*>(&thunk->u1.Function);
          if (VirtualProtect(slot, sizeof(uintptr_t), PAGE_READWRITE, &old)) {
            *slot = reinterpret_cast<uintptr_t>(rep.detour);
            VirtualProtect(slot, sizeof(uintptr_t), old, &old);
            ++count;
          }
          break;
        }
      }
    }
    return count;
  }
}

size_t patch_module(HMODULE mod, const std::vector<Replacement>& reps) {
#ifdef _MSC_VER
  __try {
    return patch_module_unsafe(mod, reps);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return 0;
  }
#else
  // MinGW/Clang 没有 MSVC SEH；只读已加载模块的 PE 头，正常情况下不会异常。
  return patch_module_unsafe(mod, reps);
#endif
}

}  // namespace

OrigApi& orig_api() { return g_orig; }

void patch_new_module(HMODULE mod) {
  static auto reps = replacements();
  if (mod && mod != g_self) patch_module(mod, reps);
}

bool install_iat_hooks(void* self_module, std::string* err) {
  g_self = self_module;
  fill_originals();
  if (!g_orig.CreateFileW || !g_orig.NtCreateFile) {
    if (err) *err = "无法解析原始文件 API 地址";
    return false;
  }
  fs_hooks_init();
  auto reps = replacements();
  size_t total = 0;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
  if (snap != INVALID_HANDLE_VALUE) {
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
      do {
        total += patch_module(me.hModule, reps);
      } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
  }
  total += patch_module(GetModuleHandleW(nullptr), reps);
  if (err) *err = "已替换 " + std::to_string(total) + " 个 IAT 项";
  dlog("IAT hooks installed: " + std::to_string(total) + " entries");
  return total > 0;
}

}  // namespace win
}  // namespace wowmod
#endif
