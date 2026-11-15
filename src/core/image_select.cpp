// 见 include/wowmod/image_select.hpp。纯逻辑，可离线验证。
// SPDX-License-Identifier: MIT
#include "wowmod/image_select.hpp"

#include <algorithm>
#include <cstring>

#include "wowmod/util.hpp"

namespace wowmod {
namespace {

constexpr uint32_t kMemImage = 0x100000;
constexpr uint32_t kMemMapped = 0x40000;

uint32_t rd32(const uint8_t* p) {
  uint32_t v = 0;
  std::memcpy(&v, p, 4);
  return v;
}
uint16_t rd16(const uint8_t* p) {
  uint16_t v = 0;
  std::memcpy(&v, p, 2);
  return v;
}

}  // namespace

PeInfo parse_pe_header(const uint8_t* hdr, size_t n) {
  PeInfo out;
  if (!hdr || n < 0x200) {
    out.error = "PE 头太短";
    return out;
  }
  if (hdr[0] != 'M' || hdr[1] != 'Z') {
    out.error = "不是 MZ";
    return out;
  }
  const uint32_t pe_off = rd32(hdr + 0x3C);
  if (pe_off > n || pe_off + 24 + 60 > n) {
    out.error = "e_lfanew 越界";
    return out;
  }
  if (rd32(hdr + pe_off) != 0x00004550u) {
    out.error = "PE 签名无效";
    return out;
  }
  out.n_sections = rd16(hdr + pe_off + 6);
  const uint16_t magic = rd16(hdr + pe_off + 24);
  out.magic = magic;
  out.is_64bit = (magic == 0x20B);
  if (magic != 0x20B && magic != 0x10B) {
    out.error = "可选头 magic 异常";
    return out;
  }
  out.size_of_image = rd32(hdr + pe_off + 24 + 56);
  if (out.size_of_image < 0x10000) {
    out.error = "SizeOfImage 太小（" + std::to_string(out.size_of_image) + "）";
    return out;
  }
  if (out.size_of_image > 512u * 1024u * 1024u) {
    out.error = "SizeOfImage 过大（" + std::to_string(out.size_of_image) + "）";
    return out;
  }
  out.ok = true;
  return out;
}

ImageSelection select_client_image(
    const std::vector<MemRegion>& regions, uint64_t peb_image_base,
    const std::function<bool(uint64_t, std::vector<uint8_t>*)>& read_header) {
  ImageSelection sel;
  auto note = [&](const std::string& s) { sel.notes.push_back(s); };

  // ---- 1. PEB 基址优先 ----
  //
  // Arctium 的 WinMemory 构造函数第一件事就是读 PEB.ImageBaseAddress，
  // 然后在那个地址上读 SizeOfImage 字节。PEB 是进程自己记录的映像基址，
  // 没有"猜"的成分。这一步能成立时，绝不应该再去看区域表。
  if (peb_image_base) {
    std::vector<uint8_t> hdr;
    if (read_header && read_header(peb_image_base, &hdr)) {
      const PeInfo pe = parse_pe_header(hdr.data(), hdr.size());
      if (pe.ok) {
        sel.image.base = peb_image_base;
        sel.image.size_of_image = pe.size_of_image;
        sel.image.from_peb = true;
        sel.image.region_type = kMemMapped;
        // PEB 基址所在的区域是 MEM_IMAGE 吗？
        for (const auto& r : regions) {
          if (r.base <= peb_image_base && peb_image_base < r.base + r.size) {
            sel.image.region_type = r.type;
            sel.image.image_backed = (r.type == kMemImage);
            break;
          }
        }
        sel.ok = true;
        note("映像基址取自 PEB: 0x" + to_hex(peb_image_base, 16) + ", SizeOfImage " +
             std::to_string(pe.size_of_image / 1048576.0) + " MB" +
             (sel.image.image_backed ? "（MEM_IMAGE）" : "（非 MEM_IMAGE：壳的映射视图）"));
        return sel;
      }
      note("PEB 基址 0x" + to_hex(peb_image_base, 16) + " 上的 PE 头不可用: " + pe.error);
    } else if (read_header) {
      note("PEB 基址 0x" + to_hex(peb_image_base, 16) + " 读不到内容");
    }
  } else {
    note("读不到 PEB.ImageBaseAddress，退回区域表筛选");
  }

  // ---- 2. 退回：在区域表里找 PE 头合法的候选 ----
  //
  // 判据必须是「PE 头里的 SizeOfImage」自洽，而不是「区域多大」。
  // 这条约束正是之前的 bug：把 RegionSize 当成 SizeOfImage，
  // 于是 108 MB / 256 MB 这种数字在轮次之间来回跳，
  // 而那些区域根本不是客户端映像。
  uint32_t best_soi = 0;
  for (const auto& r : regions) {
    if (r.size < 0x10000) continue;
    // MEM_IMAGE 优先；MEM_MAPPED 也接受（这个客户端的壳用文件映射）
    if (r.type != kMemImage && r.type != kMemMapped && r.type != 0) continue;
    std::vector<uint8_t> hdr;
    if (!read_header || !read_header(r.base, &hdr)) continue;
    const PeInfo pe = parse_pe_header(hdr.data(), hdr.size());
    if (!pe.ok) continue;
    // 关键自洽性：区域的 size 必须能容纳 SizeOfImage。
    // 不满足 = 这个 PE 头是别人的（资源段里的 DLL、壳自己的桩）。
    if (r.size + 0x10000 < pe.size_of_image) {
      note("区域 0x" + to_hex(r.base, 16) + " 的 PE 头声明 " +
           std::to_string(pe.size_of_image / 1048576.0) + " MB，但区域只有 " +
           std::to_string(r.size / 1048576.0) + " MB，丢弃");
      continue;
    }
    if (pe.size_of_image > best_soi) {
      best_soi = pe.size_of_image;
      sel.image.base = r.base;
      sel.image.size_of_image = pe.size_of_image;
      sel.image.from_peb = false;
      sel.image.region_type = r.type;
      sel.image.image_backed = (r.type == kMemImage);
    }
  }

  if (!sel.image.base) {
    sel.error = "没有找到任何一个 PE 头自洽的客户端映像。"
                "这意味着：要么客户端还没把映像映射进来（启动太早），"
                "要么它把真实代码放在了非区域表可见的地方。"
                "这不是「特征码写错了」——扫描范围都没确定，谈特征码没有意义。";
    return sel;
  }
  sel.ok = true;
  note("映像基址取自区域表: 0x" + to_hex(sel.image.base, 16) + ", SizeOfImage " +
       std::to_string(sel.image.size_of_image / 1048576.0) + " MB");
  return sel;
}

}  // namespace wowmod
