// 「到底该改哪一份映像」——这个客户端上唯一正确的判据。
//
// 为什么需要单独一个文件、单独一组测试：
//   这个 Firestorm 构建的映像布局和普通客户端不一样，我们已经在真机日志里
//   被它坑过一次，代价是「扫了 5 轮、0 命中、闪退」。
//
//   实测（用户日志）：主映像 SizeOfImage = 176.0 MB，
//   而我们报出的「主映像」先是 108.3 MB、后来涨到 256.0 MB。
//   这两个数字都只能来自「某个区域的 RegionSize」——因为 SizeOfImage 是 PE 头
//   里的定值，不会随轮次变化。也就是说我们扫的**不是客户端映像**，
//   而是它旁边一块无关的分配；真正的代码在别处，特征码当然 0 命中。
//
//   更糟的是 anti-crash 规划走的是同一个错误入口：把「最大区域」当映像是错的，
//   于是它当然找不到 Integrity/Remap（日志里「本次没有写入」就是这么来的），
//   而客户端一旦因为别的原因开始校验就会直接 0xC00000E5 闪退。
//
// 所以这里把「找映像」这件事抽成纯逻辑，唯一的输入是区域表，可以离线验证：
//   1. 基线 = PEB 里的 ImageBaseAddress（Arctium 的做法，最权威）
//   2. SizeOfImage 只认 PE 头里的值，绝不拿 RegionSize 顶替
//   3. 只有当 PEB 基址不可用时，才按「PE 头合法 + 尾部可读」去挑候选
//   4. 如果一个候选都验证不过，明确报错，而不是硬塞一个「最大区域」
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace wowmod {

// 进程里一块可读区域。由 VirtualQueryEx（或等价的离线数据）产出。
struct MemRegion {
  uint64_t base = 0;
  size_t size = 0;
  uint32_t protect = 0;
  uint32_t type = 0;      // MEM_IMAGE(0x100000) / MEM_MAPPED(0x40000) / MEM_PRIVATE
  std::string module;     // 模块名（可为空）
};

// 一个已确认是客户端映像的候选。
struct ImageCandidate {
  uint64_t base = 0;
  uint32_t size_of_image = 0;
  bool from_peb = false;      // true = 来自 PEB.ImageBaseAddress
  bool image_backed = false;  // MEM_IMAGE（唯一应该被改写的那种）
  uint32_t region_type = 0;
  std::string note;           // 人话，写进报告
};

struct ImageSelection {
  bool ok = false;
  std::string error;
  ImageCandidate image;
  std::vector<std::string> notes;
};

// PE 头解析结果（只看选映像需要的字段）。
struct PeInfo {
  bool ok = false;
  std::string error;
  uint32_t size_of_image = 0;
  uint16_t n_sections = 0;
  uint16_t magic = 0;        // 0x20B = PE32+
  bool is_64bit = false;
};

// 从 PE 头的前 0x1000 字节解析出 SizeOfImage 等字段。
PeInfo parse_pe_header(const uint8_t* hdr, size_t n);

// 选出「客户端映像」。
//
//   regions        : 进程区域表（base/size/type 必须来自 VirtualQueryEx，
//                    不能是「我猜的」）
//   peb_image_base : PEB.ImageBaseAddress，0 表示读不到
//   read_header    : 回调用它读某地址的前 0x1000 字节；返回 false/短读视为读不到
ImageSelection select_client_image(const std::vector<MemRegion>& regions,
                                   uint64_t peb_image_base,
                                   const std::function<bool(uint64_t, std::vector<uint8_t>*)>&
                                       read_header);

}  // namespace wowmod
