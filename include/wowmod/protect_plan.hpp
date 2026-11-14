// 「给一个页挑可写保护值」的纯逻辑（无平台依赖，可测试）。
//
// 为什么单独抽出来：这段判断错了的表现是 VirtualProtectEx 返回
// ERROR_INVALID_PARAMETER(87)，几乎没有提示，很难猜。
//
// 真实踩到的坑：WoW/Firestorm 客户端映像那块 108MB 是 MEM_MAPPED 的映像节，
// 对它请求 PAGE_EXECUTE_READWRITE 会失败并返回 87 —— 映像节的页保护必须与
// 原始节属性兼容，不能中途把非执行页变成可执行页。正确值是与 RWX 语义等价、
// 但映像节合法（写时复制、不落盘）的 PAGE_EXECUTE_WRITECOPY。
//
// 数值直接写死，避免依赖 windows.h：
//   PAGE_READWRITE          = 0x04
//   PAGE_WRITECOPY          = 0x08
//   PAGE_EXECUTE_READWRITE  = 0x40
//   PAGE_EXECUTE_WRITECOPY  = 0x80
//   MEM_MAPPED              = 0x40000
//   MEM_IMAGE               = 0x100000
// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <vector>

namespace wowmod {

enum : uint32_t {
  kPageReadWrite = 0x04,
  kPageWriteCopy = 0x08,
  kPageExecuteReadWrite = 0x40,
  kPageExecuteWriteCopy = 0x80,
  kMemMapped = 0x40000,
  kMemImage = 0x100000,
};

// 按优先级返回该页可写的保护值；调用方依次尝试，第一个成功的就是最合适的。
inline std::vector<uint32_t> writable_protect_candidates(uint32_t type, uint32_t protect) {
  const uint32_t orig = protect & 0xFF;
  const bool mapped = (type == kMemMapped || type == kMemImage);
  if (mapped) {
    // 映像节：写时复制是唯一合法的可写语义。
    // 若原本就可执行，优先保执行属性；否则 WRITECOPY 也够（我们只需要写）。
    if (orig == kPageExecuteReadWrite || orig == kPageExecuteWriteCopy ||
        orig == kPageExecuteReadWrite)
      return {kPageExecuteWriteCopy, kPageWriteCopy, kPageReadWrite};
    return {kPageExecuteWriteCopy, kPageWriteCopy, kPageReadWrite};
  }
  // 私有内存：RWX 合法
  return {kPageExecuteReadWrite, kPageReadWrite};
}

}  // namespace wowmod
