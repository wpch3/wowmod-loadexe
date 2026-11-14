// 在【运行中的进程】里找出所有候选客户端映像。
//
// 为什么必须这么做（这是本项目最关键的一个发现）：
//   把 12.0.7 Firestorm 的崩溃转储逐区域核对后可以看到：
//     * 模块表里的主模块基址 0x140000000，大小约 113 MB；
//     * 但真正带 WOWSTATIC_12_0_7_67808 标记、有 28 MB 真实数据的那块内存
//       在 0x118000000 —— 一个【独立分配】，不在模块映像内；
//     * 模块基址内被记录的区域只有 31 MB 的真实数据，其余是未提交/被换出。
//   也就是说加载壳把真实客户端解密到了别的分配里。任何「按模块基址扫描特征」
//   或「只看磁盘 exe」的做法都必然找不到 hook 点 —— 这正是之前所有尝试失败
//   的根本原因，而不是"特征写错了"。
//
// 因此这里改成：枚举进程所有已提交区域 -> 找出所有 PE 映像与含标记的块 ->
// 逐个分析。这样无论客户端把真实代码放哪里都能覆盖到。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wowmod {
namespace win {

struct ScannedImage {
  uint64_t base = 0;
  size_t size = 0;
  bool executable = false;
  bool has_pe_header = false;
  size_t marker_hits = 0;         // 命中的 loose-file 标记字符串个数
  std::string first_marker;       // 第一个命中的标记
  std::string module_name;        // 若属于某个已加载模块，给出模块名
  uint32_t pe_timestamp = 0;
  std::vector<uint8_t> bytes;     // 读出来的映像内容（可能被裁剪到上限）
  size_t committed_bytes = 0;     // 实际读到的字节数
};

// 枚举进程里所有候选映像。max_bytes 限制单个映像的读取上限（默认 192 MB）。
std::vector<ScannedImage> scan_process_images(HANDLE process, size_t max_bytes = 192u << 20);

// 把核心的可执行映像原样写到磁盘，供离线用 IDA/x64dbg 分析。
// 这样即使特征码全部落空，也不必让用户反复重跑 —— 一次就能拿到分析素材。
// 写出的是【运行时映像】（RVA == 文件偏移），报告里会另存一份区域清单。
struct DumpResult {
  std::string path;
  uint64_t base = 0;
  size_t marker_hits = 0;   // 这块映像里客户端标记字符串的命中数；0 = 多半不是客户端本体
  size_t written = 0;
  bool ok = false;
  std::string error;
};

// 导出「含客户端标记」的映像 —— 也就是真正装着 CASC/FileDataID 代码的那一块。
//
// 之前只收「可执行」区域，结果漏掉了 108 MB 的主客户端映像：
// 它的保护属性是 PAGE_READONLY(0x004)，不是可执行，于是导出的 4 个文件
// 全是运行库代码块（实测都不含 CASC/FileDataID/.flavor.info 任何一个串）。
// 现在改成按「标记命中数」排序，优先导出真正有客户端数据的映像。
//
// 传入已扫描好的映像，避免二次读取 100MB+。
std::vector<DumpResult> dump_client_images(const std::vector<ScannedImage>& images,
                                           const std::string& out_dir,
                                           size_t max_images = 4);

// 按 PE 节结构导出【指定模块】的完整内存映像。
//
// 为什么需要它（这是本项目的关键发现之一）：
//   把用户的 exe 拉下来逐节算熵后确认：.text 共 56.2 MB，**熵 = 8.00**
//   （理论最大值），只有入口点前 0x28 字节是明文桩：
//       48 83 EC 28 48 8B 05 ... （调用 Wow_loader.dll 初始化）
//   之后立刻变成随机字节。也就是说磁盘上的 exe 里根本没有客户端代码，
//   .text 是加密载荷，字符串所在的 .rdata 仍是明文。
//   因此「从磁盘 exe 提取特征码」在原理上不可行 —— 不是特征码过时。
//
//   而运行时映像里代码是解密好的（分析报告能在 rva=0x33e1890 成功反汇编，
//   lea rdx 精确指向 rva=0x35c4890 的字符串）。所以只能从内存里拿。
//
// module 为空 = 主 exe。失败时 err 给原因。
struct ModuleDump {
  std::string path;
  uint64_t base = 0;
  size_t size_of_image = 0;
  size_t written = 0;
  bool ok = false;
  std::string error;
  std::vector<std::string> sections;   // 每节的 "名称 VA 大小 类型"，供报告
  // ---- 解密进度度量（用来判断"现在抓是不是太早"）----
  size_t text_checked = 0;   // 采样的可执行页数
  size_t text_low_entropy = 0;  // 其中熵估算 < 7.0 的页数（= 明文代码）
};

// 用 4 KB 采样页估算可执行段里有几成已经是明文。
// 壳是【按页惰性解密】的：没跑到的页仍是密文（熵≈8），跑到的页是明文（熵 5~7）。
// 所以"明文页比例不再上升"就是一个可靠的导出时机信号，
// 比固定 Sleep 靠谱 —— 之前 dump 只有 9.6% 明文就是这么来的。
ModuleDump dump_module_full(HANDLE process, const std::string& module_name,
                            const std::string& out_path);

// 只探测（不保留内容），用于轮询判断"解密完成没有"。
bool process_has_client_markers(HANDLE process, std::string* first_marker);

}  // namespace win
}  // namespace wowmod
#endif
