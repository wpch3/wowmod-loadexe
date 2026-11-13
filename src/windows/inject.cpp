// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/inject.hpp"

#include <string>

#include "wowmod/util.hpp"

namespace wowmod {
namespace win {

bool inject_dll(HANDLE process, const std::wstring& dll_path, std::string* err) {
  if (!process) { if (err) *err = "无效的进程句柄"; return false; }
  if (!file_exists(normalize_path(wowmod::wide_to_utf8(dll_path)))) {
    if (err) *err = "找不到注入模块: " + normalize_path(wowmod::wide_to_utf8(dll_path));
    return false;
  }
  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  if (!k32) { if (err) *err = "无法取得 kernel32"; return false; }
  auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(k32, "LoadLibraryW"));
  if (!load_library) { if (err) *err = "无法解析 LoadLibraryW"; return false; }

  size_t bytes = (dll_path.size() + 1) * sizeof(wchar_t);
  void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote) { if (err) *err = "VirtualAllocEx 失败 (" + std::to_string(GetLastError()) + ")"; return false; }
  SIZE_T written = 0;
  if (!WriteProcessMemory(process, remote, dll_path.c_str(), bytes, &written) || written != bytes) {
    if (err) *err = "WriteProcessMemory 失败 (" + std::to_string(GetLastError()) + ")";
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return false;
  }
  HANDLE thread = CreateRemoteThread(process, nullptr, 0, load_library, remote, 0, nullptr);
  if (!thread) {
    if (err) *err = "CreateRemoteThread 失败 (" + std::to_string(GetLastError()) + ")";
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return false;
  }
  DWORD wait = WaitForSingleObject(thread, 15000);
  DWORD code = 0;
  GetExitCodeThread(thread, &code);
  CloseHandle(thread);
  VirtualFreeEx(process, remote, 0, MEM_RELEASE);
  if (wait == WAIT_TIMEOUT) { if (err) *err = "注入超时（DllMain 卡住）"; return false; }
  if (code == 0) {
    if (err) *err = "LoadLibraryW 返回 NULL：检查 DLL 位数是否与客户端一致、依赖是否齐全";
    return false;
  }
  if (err) *err = "注入成功，模块基址 0x" + to_hex(code, 8);
  return true;
}

}  // namespace win
}  // namespace wowmod
#endif
