// Arctium 特征码扫描（Windows 运行时映像）。
//
// 为什么必须用特征码，而不是字符串交叉引用：
//   之前用 "Locally overridden files" 找引用，命中的是崩溃日志格式化函数
//   （栈帧 0x140、"Locally overridden files" 进 rdx），正常流程调用 0 次。
//   打它 = 打坏崩溃处理器本身，客户端只会以 EXCEPTION_INTERNAL_ERROR 死掉，
//   连日志都写不出来。
//
//   Arctium（MIT，开源）根本不看字符串，它用【函数序言特征码】定位：
//     CustomFileIdHook = 48 89 5C 24 08 57 48 83 EC 20 48 8B ? 48 ? ? 48 ? ? ? ? ? ? E8 ..
//   这是「文件打开函数」的入口：rdx = FileDataID，返回 rax = 路径指针。
//
// 本模块的职责：把这套特征码拿运行中的 12.0.7 映像去匹配，并且【诚实报告】
// 匹配了几个、匹配在哪个区、周边代码像不像文件系统函数。绝不猜。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "wowmod/arctium_sigs.hpp"
#include "wowmod/hooks.hpp"
#include "windows/scan_images.hpp"
#include "wowmod/json.hpp"
#include "wowmod/util.hpp"

namespace wowmod {
namespace win {

using ArctiumSignature = wowmod::ArctiumSignatureSpec;

struct SigHit {
  std::string name;
  std::string pattern;
  int patch_offset = 0;
  uint64_t match_va = 0;      // 匹配起点虚拟地址
  uint64_t patch_va = 0;      // match_va + patch_offset（Arctium 实际改写的位置）
  uint64_t image_base = 0;
  size_t image_size = 0;
  size_t match_count = 0;     // 整幅映像里出现了几次（>1 = 特征太弱，不可直接使用）
  bool image_executable = false;
  std::string image_note;     // 所属区域说明（模块名 或 匿名可执行区）
  std::vector<uint8_t> head;  // 匹配处前 64 字节，供人工核对
  int semantic_score = 0;     // CustomFileIdHook 的语义判别分（0..8，8=确证）
  std::string verdict;        // 结论：unique / ambiguous / near-miss
};

struct SigScanResult {
  std::string exe;
  uint32_t pid = 0;
  size_t images_scanned = 0;
  size_t bytes_scanned = 0;
  std::vector<SigHit> hits;
  std::vector<std::string> notes;   // 每个特征码未命中的原因
  // 扫描时读进来的映像（含字节）。留给 --dump 直接写盘，避免二次读 100MB+。
  std::vector<ScannedImage> images;
  Json to_json() const;
  Json to_text_report() const;
};

// 对已启动的客户端做一次特征码扫描。不修改目标进程任何字节。
SigScanResult scan_arctium_signatures(HANDLE process, const std::string& exe_path);

}  // namespace win
}  // namespace wowmod
#endif
