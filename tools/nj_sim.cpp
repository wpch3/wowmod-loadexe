// 端到端模拟 plan_branch_patches 的三条路径，
// 用用户日志里的真实字节验证 known_rva 直通能否产出可用的 BranchPatch。
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// 用户日志原文
static const uint8_t kFileId16[16] = {0x01, 0x0F, 0x84, 0x9C, 0x00, 0x00, 0x00, 0x48,
                                      0x8B, 0x0D, 0x4C, 0x01, 0xFD, 0x00, 0x8B, 0xD6};
static const uint8_t kFilePath16[16] = {0x01, 0x0F, 0x84, 0xC0, 0x00, 0x00, 0x00, 0x48,
                                        0x8B, 0x0D, 0x6A, 0xFF, 0xFC, 0x00, 0x44, 0x89};

int main() {
  // 构造一个 108MB 的映像，在正确 RVA 处放入真实字节，其余填 0xCC
  const size_t n = 0x6C4E000;  // 108.3 MB
  const size_t rva1 = 0x33D7976, rva2 = 0x33D7B58;
  std::vector<uint8_t> img(n, 0xCC);
  std::memcpy(img.data() + rva1, kFileId16, 16);
  std::memcpy(img.data() + rva2, kFilePath16, 16);

  // === 模拟 known_rva 直通 ===
  struct Res { bool ok; size_t rva; int je_at; uint64_t patch_va; uint32_t rel; int patch_offset; };
  auto try_known = [&](size_t rva, int patch_offset) -> Res {
    Res r{false, rva, -1, 0, 0, patch_offset};
    if (rva + 8 > img.size()) return r;
    const uint8_t* q = img.data() + rva;
    const bool looks_like_je =
        (q[0] == 0x0F && q[1] == 0x84) || (q[0] == 0x01 && q[1] == 0x0F && q[2] == 0x84);
    if (!looks_like_je) return r;
    // verify_and_fix_hits 等价逻辑
    const int expected_je_at = patch_offset - 2;  // 3-2 = 1
    int je_at = -1;
    if (expected_je_at >= 0 && expected_je_at + 6 <= 16 && q[expected_je_at] == 0x0F &&
        q[expected_je_at + 1] == 0x84) {
      je_at = expected_je_at;
    }
    if (je_at < 0) return r;
    uint8_t rel32[4];
    std::memcpy(rel32, q + je_at + 2, 4);
    const int32_t rel = static_cast<int32_t>(rel32[0] | (rel32[1] << 8) | (rel32[2] << 16) |
                                            (uint32_t(rel32[3]) << 24));
    if (rel <= 0 || rel > 0x100000) return r;  // 前向跳转合理性
    r.ok = true;
    r.je_at = je_at;
    r.rel = static_cast<uint32_t>(rel);
    return r;
  };

  auto a = try_known(rva1, 3);
  auto b = try_known(rva2, 3);
  std::printf("LoadByFileIdAlternate   RVA 0x%zX -> ok=%d je_at=%d rel=0x%X\n", rva1, a.ok, a.je_at,
              a.rel);
  std::printf("LoadByFilePathAlternate RVA 0x%zX -> ok=%d je_at=%d rel=0x%X\n", rva2, b.ok, b.je_at,
              b.rel);
  std::printf("\n两条都应 ok=1、je_at=1（01 0F 84 里的 0F 84）\n");
  return (a.ok && b.ok && a.je_at == 1 && b.je_at == 1) ? 0 : 1;
}
