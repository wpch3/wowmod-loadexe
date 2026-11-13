// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/fs_hooks.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "windows/runtime.hpp"

namespace wowmod {
namespace win {

namespace {

constexpr NTSTATUS kStatusObjectNameNotFound = static_cast<NTSTATUS>(0xC0000034L);

CRITICAL_SECTION g_lock;
bool g_lock_ready = false;
volatile LONG g_hits = 0;
volatile LONG g_pseudo_counter = 0;

struct FindState {
  std::vector<WIN32_FIND_DATAW> extras;
  size_t index = 0;
  bool real_handle = true;
};

std::unordered_map<HANDLE, FindState> g_find_states;

bool is_pseudo(HANDLE h) {
  uintptr_t v = reinterpret_cast<uintptr_t>(h);
  return (v & 0xFFFFFFFFFFFF0000ULL) == 0x574F574D0000ULL;  // "WOWM"
}

std::wstring ansi_to_wide(LPCSTR s) {
  if (!s) return L"";
  int n = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
  if (n <= 1) return L"";
  std::wstring w(static_cast<size_t>(n - 1), L'\0');
  MultiByteToWideChar(CP_ACP, 0, s, -1, w.data(), n);
  return w;
}

std::wstring make_nt_path(const std::string& utf8_path) {
  std::wstring w = utf8_to_wide(to_native_path(utf8_path));
  if (w.size() >= 4 && w[0] == L'\\' && w[1] == L'?' && w[2] == L'?' && w[3] == L'\\') return w;
  if (w.rfind(L"\\Device\\", 0) == 0) return w;
  return L"\\??\\" + w;
}

void note_hit(const Redirect& r) {
  LONG n = InterlockedIncrement(&g_hits);
  if ((n & 63) == 1) dlog("overlay hits=" + std::to_string(n) + " last=" + r.key + " -> " + r.path);
}

void init_unicode(UNICODE_STRING* us, const std::wstring& w) {
  us->Length = static_cast<USHORT>(w.size() * sizeof(wchar_t));
  us->MaximumLength = static_cast<USHORT>(us->Length + sizeof(wchar_t));
  us->Buffer = const_cast<PWSTR>(w.c_str());
}

std::wstring object_name(POBJECT_ATTRIBUTES oa) {
  if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer) return L"";
  return std::wstring(oa->ObjectName->Buffer, oa->ObjectName->Length / sizeof(wchar_t));
}

void set_find_name(WIN32_FIND_DATAW* f, const std::string& name, bool directory, uint64_t size) {
  if (!f) return;
  std::memset(f, 0, sizeof(*f));
  std::wstring w = utf8_to_wide(name);
  size_t n = std::min(w.size(), static_cast<size_t>(MAX_PATH - 1));
  std::copy(w.begin(), w.begin() + static_cast<std::ptrdiff_t>(n), f->cFileName);
  f->cFileName[n] = L'\0';
  f->dwFileAttributes = directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
  f->nFileSizeHigh = static_cast<DWORD>(size >> 32);
  f->nFileSizeLow = static_cast<DWORD>(size & 0xFFFFFFFFu);
}

std::vector<WIN32_FIND_DATAW> build_extras(LPCWSTR requested) {
  std::vector<WIN32_FIND_DATAW> out;
  if (!requested) return out;
  auto dir = directory_key(std::wstring(requested));
  if (!dir) return out;
  const auto& rt = runtime();
  for (const auto& name : rt.vfs.extra_names(*dir)) {
    std::string real = join_path(rt.cfg.client.game_dir, join_path(*dir, name));
    if (file_exists(real) || dir_exists(real)) continue;
    bool directory = overlay_is_directory(*dir, name);
    uint64_t size = 0;
    if (!directory) {
      auto hit = rt.vfs.resolve_path(join_path(*dir, name));
      if (hit) size = hit->size;
    }
    WIN32_FIND_DATAW f{};
    set_find_name(&f, name, directory, size);
    out.push_back(f);
  }
  return out;
}

HANDLE register_find_state(HANDLE real, bool real_handle, LPCWSTR requested) {
  auto extras = build_extras(requested);
  if (extras.empty()) return real;
  EnterCriticalSection(&g_lock);
  HANDLE key = real;
  if (!real_handle) {
    LONG id = InterlockedIncrement(&g_pseudo_counter);
    key = reinterpret_cast<HANDLE>(0x574F574D0000ULL | static_cast<uintptr_t>(id));
  }
  FindState st;
  st.extras = std::move(extras);
  st.real_handle = real_handle;
  g_find_states[key] = std::move(st);
  LeaveCriticalSection(&g_lock);
  if (!real_handle) SetLastError(ERROR_SUCCESS);
  return key;
}

}  // namespace

void fs_hooks_init() {
  if (!g_lock_ready) { InitializeCriticalSection(&g_lock); g_lock_ready = true; }
}

HANDLE WINAPI DetourCreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                DWORD disp, DWORD flags, HANDLE tmpl) {
  OrigApi& o = orig_api();
  if (name) {
    Redirect r = resolve_redirect(std::wstring(name));
    if (r.kind == RedirectKind::Block) { SetLastError(ERROR_FILE_NOT_FOUND); return INVALID_HANDLE_VALUE; }
    if (r.kind == RedirectKind::Replace) {
      note_hit(r);
      std::wstring w = utf8_to_wide(to_native_path(r.path));
      return o.CreateFileW(w.c_str(), access, share, sa, disp, flags, tmpl);
    }
  }
  return o.CreateFileW(name, access, share, sa, disp, flags, tmpl);
}

HANDLE WINAPI DetourCreateFileA(LPCSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                DWORD disp, DWORD flags, HANDLE tmpl) {
  OrigApi& o = orig_api();
  if (name) {
    Redirect r = resolve_redirect(ansi_to_wide(name));
    if (r.kind == RedirectKind::Block) { SetLastError(ERROR_FILE_NOT_FOUND); return INVALID_HANDLE_VALUE; }
    if (r.kind == RedirectKind::Replace) {
      note_hit(r);
      std::wstring w = utf8_to_wide(to_native_path(r.path));
      return o.CreateFileW(w.c_str(), access, share, sa, disp, flags, tmpl);
    }
  }
  return o.CreateFileA(name, access, share, sa, disp, flags, tmpl);
}

DWORD WINAPI DetourGetFileAttributesW(LPCWSTR name) {
  OrigApi& o = orig_api();
  if (name) {
    Redirect r = resolve_redirect(std::wstring(name));
    if (r.kind == RedirectKind::Block) { SetLastError(ERROR_FILE_NOT_FOUND); return INVALID_FILE_ATTRIBUTES; }
    if (r.kind == RedirectKind::Replace) return o.GetFileAttributesW(utf8_to_wide(to_native_path(r.path)).c_str());
  }
  return o.GetFileAttributesW(name);
}

DWORD WINAPI DetourGetFileAttributesA(LPCSTR name) {
  OrigApi& o = orig_api();
  if (name) {
    Redirect r = resolve_redirect(ansi_to_wide(name));
    if (r.kind == RedirectKind::Block) { SetLastError(ERROR_FILE_NOT_FOUND); return INVALID_FILE_ATTRIBUTES; }
    if (r.kind == RedirectKind::Replace) return o.GetFileAttributesW(utf8_to_wide(to_native_path(r.path)).c_str());
  }
  return o.GetFileAttributesA(name);
}

BOOL WINAPI DetourGetFileAttributesExW(LPCWSTR name, GET_FILEEX_INFO_LEVELS level, LPVOID data) {
  OrigApi& o = orig_api();
  if (name) {
    Redirect r = resolve_redirect(std::wstring(name));
    if (r.kind == RedirectKind::Block) { SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
    if (r.kind == RedirectKind::Replace)
      return o.GetFileAttributesExW(utf8_to_wide(to_native_path(r.path)).c_str(), level, data);
  }
  return o.GetFileAttributesExW(name, level, data);
}

HANDLE WINAPI DetourFindFirstFileW(LPCWSTR name, LPWIN32_FIND_DATAW data) {
  OrigApi& o = orig_api();
  HANDLE h = o.FindFirstFileW(name, data);
  if (h == INVALID_HANDLE_VALUE) {
    auto extras = build_extras(name);
    if (!extras.empty()) return register_find_state(h, false, name);
    return h;
  }
  return register_find_state(h, true, name);
}

HANDLE WINAPI DetourFindFirstFileExW(LPCWSTR name, FINDEX_INFO_LEVELS level, LPVOID data,
                                     FINDEX_SEARCH_OPS op, LPVOID filter, DWORD flags) {
  OrigApi& o = orig_api();
  HANDLE h = o.FindFirstFileExW(name, level, data, op, filter, flags);
  if (h == INVALID_HANDLE_VALUE) {
    auto extras = build_extras(name);
    if (!extras.empty()) return register_find_state(h, false, name);
    return h;
  }
  return register_find_state(h, true, name);
}

BOOL WINAPI DetourFindNextFileW(HANDLE h, LPWIN32_FIND_DATAW data) {
  OrigApi& o = orig_api();
  EnterCriticalSection(&g_lock);
  auto it = g_find_states.find(h);
  if (it != g_find_states.end()) {
    FindState* st = &it->second;
    if (st->real_handle) {
      BOOL ok = o.FindNextFileW(h, data);
      if (ok) { LeaveCriticalSection(&g_lock); return TRUE; }
    }
    if (st->index < st->extras.size()) {
      if (data) *data = st->extras[st->index++];
      LeaveCriticalSection(&g_lock);
      SetLastError(ERROR_SUCCESS);
      return TRUE;
    }
    LeaveCriticalSection(&g_lock);
    SetLastError(ERROR_NO_MORE_FILES);
    return FALSE;
  }
  LeaveCriticalSection(&g_lock);
  return o.FindNextFileW(h, data);
}

BOOL WINAPI DetourFindClose(HANDLE h) {
  OrigApi& o = orig_api();
  bool pseudo = is_pseudo(h);
  if (g_lock_ready) {
    EnterCriticalSection(&g_lock);
    g_find_states.erase(h);
    LeaveCriticalSection(&g_lock);
  }
  if (pseudo) return TRUE;
  return o.FindClose(h);
}

HMODULE WINAPI DetourLoadLibraryW(LPCWSTR name) {
  OrigApi& o = orig_api();
  HMODULE m = o.LoadLibraryW(name);
  if (m) patch_new_module(m);
  return m;
}

HMODULE WINAPI DetourLoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags) {
  OrigApi& o = orig_api();
  HMODULE m = o.LoadLibraryExW(name, file, flags);
  if (m && !(flags & DONT_RESOLVE_DLL_REFERENCES)) patch_new_module(m);
  return m;
}

NTSTATUS NTAPI DetourNtCreateFile(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES oa,
                                  PIO_STATUS_BLOCK iosb, PLARGE_INTEGER alloc, ULONG attrs,
                                  ULONG share, ULONG disposition, ULONG options, PVOID ea, ULONG ea_len) {
  OrigApi& o = orig_api();
  std::wstring req = object_name(oa);
  if (!req.empty()) {
    Redirect r = resolve_redirect(req);
    if (r.kind == RedirectKind::Block) return kStatusObjectNameNotFound;
    if (r.kind == RedirectKind::Replace) {
      note_hit(r);
      std::wstring nt = make_nt_path(r.path);
      UNICODE_STRING us;
      init_unicode(&us, nt);
      OBJECT_ATTRIBUTES copy = *oa;
      copy.ObjectName = &us;
      copy.RootDirectory = nullptr;
      return o.NtCreateFile(handle, access, &copy, iosb, alloc, attrs, share, disposition, options, ea, ea_len);
    }
  }
  return o.NtCreateFile(handle, access, oa, iosb, alloc, attrs, share, disposition, options, ea, ea_len);
}

NTSTATUS NTAPI DetourNtOpenFile(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES oa,
                                PIO_STATUS_BLOCK iosb, ULONG share, ULONG options) {
  OrigApi& o = orig_api();
  std::wstring req = object_name(oa);
  if (!req.empty()) {
    Redirect r = resolve_redirect(req);
    if (r.kind == RedirectKind::Block) return kStatusObjectNameNotFound;
    if (r.kind == RedirectKind::Replace) {
      note_hit(r);
      std::wstring nt = make_nt_path(r.path);
      UNICODE_STRING us;
      init_unicode(&us, nt);
      OBJECT_ATTRIBUTES copy = *oa;
      copy.ObjectName = &us;
      copy.RootDirectory = nullptr;
      return o.NtOpenFile(handle, access, &copy, iosb, share, options);
    }
  }
  return o.NtOpenFile(handle, access, oa, iosb, share, options);
}

}  // namespace win
}  // namespace wowmod
#endif
