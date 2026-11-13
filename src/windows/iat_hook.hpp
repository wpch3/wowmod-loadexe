// IAT 级 Hook：只hook稳定的 Win32/ntdll 文件 API，不碰客户端内部代码。
// 这是"通用版本"的基础 —— 这些 API 在 1.x ~ 12.x 所有客户端里都一样。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32

#include <windows.h>
#include <winternl.h>

#include <string>

namespace wowmod {
namespace win {

using CreateFileW_t = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using CreateFileA_t = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using GetFileAttributesW_t = DWORD(WINAPI*)(LPCWSTR);
using GetFileAttributesA_t = DWORD(WINAPI*)(LPCSTR);
using GetFileAttributesExW_t = BOOL(WINAPI*)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
using FindFirstFileW_t = HANDLE(WINAPI*)(LPCWSTR, LPWIN32_FIND_DATAW);
using FindFirstFileExW_t = HANDLE(WINAPI*)(LPCWSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);
using FindNextFileW_t = BOOL(WINAPI*)(HANDLE, LPWIN32_FIND_DATAW);
using FindClose_t = BOOL(WINAPI*)(HANDLE);
using LoadLibraryW_t = HMODULE(WINAPI*)(LPCWSTR);
using LoadLibraryExW_t = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
using NtCreateFile_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                       PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
using NtOpenFile_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);

struct OrigApi {
  CreateFileW_t CreateFileW = nullptr;
  CreateFileA_t CreateFileA = nullptr;
  GetFileAttributesW_t GetFileAttributesW = nullptr;
  GetFileAttributesA_t GetFileAttributesA = nullptr;
  GetFileAttributesExW_t GetFileAttributesExW = nullptr;
  FindFirstFileW_t FindFirstFileW = nullptr;
  FindFirstFileExW_t FindFirstFileExW = nullptr;
  FindNextFileW_t FindNextFileW = nullptr;
  FindClose_t FindClose = nullptr;
  LoadLibraryW_t LoadLibraryW = nullptr;
  LoadLibraryExW_t LoadLibraryExW = nullptr;
  NtCreateFile_t NtCreateFile = nullptr;
  NtOpenFile_t NtOpenFile = nullptr;
};

OrigApi& orig_api();

// 安装 hook；成功返回 true。失败只影响覆盖能力，不会阻止客户端启动。
bool install_iat_hooks(void* self_module, std::string* err);

// 为运行时新加载的模块补装 IAT hook。
void patch_new_module(HMODULE mod);

}  // namespace win
}  // namespace wowmod
#endif
