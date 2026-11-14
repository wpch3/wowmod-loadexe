/*
 * wowmod_rt.dll 的链接布局。
 *
 * 为什么需要它：
 *   客户端加载层会对 DLL 做检查（是否真的是 DLL、有没有 DllMain）。
 *   把 PE 头里的 IMAGE_FILE_DLL 标志去掉、并把入口点指向一个自定义函数，
 *   可以让「被当成库加载」和「被直接跳进去执行」两种方式都能工作，
 *   而不再依赖 CreateRemoteThread(LoadLibraryW) 这一条可能被拒绝的路径。
 *
 * 保留导出表：外部仍可以 GetProcAddress 调用 wowmod_rt_install 等接口。
 * SPDX-License-Identifier: MIT
 */
ENTRY(wowmod_rt_entry)

SECTIONS
{
  . = SIZEOF_HEADERS;

  .text : {
    *(.text .text.*)
  }

  .rdata : {
    *(.rdata .rdata.*)
    *(.rodata .rodata.*)
  }

  .data : {
    *(.data .data.*)
  }

  .pdata : {
    *(.pdata)
  }

  .xdata : {
    *(.xdata)
  }

  .bss : {
    *(.bss .bss.*)
  }

  .idata : {
    *(.idata)
  }

  .CRT : {
    *(.CRT)
  }

  .tls : {
    *(.tls)
  }

  .reloc : {
    *(.reloc)
  }

  /DISCARD/ : {
    *(.comment)
    *(.eh_frame*)
  }
}
