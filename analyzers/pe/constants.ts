"use strict";

type OptionEntry = [number, string, string?];

// Microsoft PE format, "Machine Types":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
// Keep one canonical label per numeric value even when the spec lists legacy aliases.
export const MACHINE: OptionEntry[] = [
  [0x0000, "UNKNOWN", "Applies to any machine type"],
  [0x0184, "Alpha AXP", "Alpha AXP, 32-bit address space"],
  [0x0284, "Alpha 64", "Alpha 64, 64-bit address space"],
  [0x01d3, "Matsushita AM33", "Embedded 32-bit CPU family"],
  [0x8664, "x86-64 (AMD64)", "x64"],
  [0x01c0, "ARM little-endian", "Classic 32-bit ARM code"],
  [0xaa64, "ARM64", "64-bit ARM code (AArch64), little-endian"],
  [0xa641, "ARM64EC", "Interoperates between native ARM64 and emulated x64 code"],
  [0xa64e, "ARM64X", "Allows native ARM64 and ARM64EC code to coexist in one file"],
  [0x01c4, "ARM Thumb-2 (ARMNT)", "ARM code using the more compact Thumb-2 instructions"],
  [0x0ebc, "EFI Byte Code", "Portable EFI/UEFI bytecode not tied to one CPU family"],
  [0x014c, "x86 (I386)", "Intel 386 or later processors and compatible processors"],
  [0x0200, "Intel Itanium (IA-64)", "Intel Itanium processor family"],
  [0x6232, "LoongArch 32-bit", "LoongArch 32-bit processor family"],
  [0x6264, "LoongArch 64-bit", "LoongArch 64-bit processor family"],
  [0x9041, "M32R", "Mitsubishi embedded CPU family, little-endian"],
  [0x0266, "MIPS16", "MIPS variant with shorter instructions to save space"],
  [0x0366, "MIPS with FPU", "MIPS target with hardware floating-point support"],
  [0x0466, "MIPS16 with FPU", "Compact-instruction MIPS target with floating-point support"],
  [0x01f0, "Power PC little-endian", "PowerPC code stored in little-endian byte order"],
  [0x01f1, "Power PC with floating point support", "PowerPC target with hardware floating-point support"],
  [0x0160, "MIPS I big-endian", "MIPS I compatible 32-bit big endian"],
  [0x0162, "MIPS I little-endian", "MIPS I compatible 32-bit little endian"],
  [0x0166, "MIPS R4000", "MIPS III compatible 64-bit little endian"],
  [0x0168, "MIPS R10000", "MIPS IV compatible 64-bit little endian"],
  [0x5032, "RISC-V32", "RISC-V 32-bit address space"],
  [0x5064, "RISC-V64", "RISC-V 64-bit address space"],
  [0x5128, "RISC-V128", "RISC-V 128-bit address space"],
  [0x01a2, "SH3", "Hitachi SH3 embedded CPU family"],
  [0x01a3, "SH3 DSP", "SH3 variant with digital signal processing extensions"],
  [0x01a6, "SH4", "Hitachi SH4 embedded CPU family"],
  [0x01a8, "SH5", "Hitachi SH5 CPU family"],
  [0x01c2, "Thumb", "ARM Thumb code: compact instructions often used to save space"],
  [0x0169, "MIPS little-endian WCE v2", "Older Windows CE target for little-endian MIPS systems"]
];

// Microsoft PE format, "Windows Subsystem":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#windows-subsystem
export const SUBSYSTEMS: OptionEntry[] = [
  [0, "Unknown", "An unknown subsystem"],
  [1, "Native", "Used by drivers and low-level Windows processes, not normal desktop apps"],
  [2, "Windows GUI", "Normal graphical Windows application"],
  [3, "Windows CUI", "Console or terminal-style Windows application"],
  [5, "OS/2 CUI", "Character-mode application for OS/2"],
  [7, "POSIX CUI", "Character-mode application for POSIX environments"],
  [8, "Native Windows", "Native Win9x driver"],
  [9, "Windows CE GUI", "Graphical application for Windows CE devices"],
  [10, "EFI Application", "Program meant to run under EFI or UEFI firmware"],
  [11, "EFI Boot Service Driver", "Firmware driver available while boot services are active"],
  [12, "EFI Runtime Driver", "Firmware driver that remains available after boot"],
  [13, "EFI ROM", "Firmware image intended for an EFI or UEFI ROM"],
  [14, "XBOX", "Subsystem used by Xbox binaries"],
  [16, "Windows Boot Application", "Program that runs during Windows boot, before normal apps"]
];

export const CHAR_FLAGS: OptionEntry[] = [
  [0x0001, "RELOCS_STRIPPED", "Relocations stripped from the file"],
  [0x0002, "EXECUTABLE_IMAGE", "Image is valid and can run"],
  [0x0004, "LINE_NUMS_STRIPPED", "COFF line numbers removed (deprecated)"],
  [0x0008, "LOCAL_SYMS_STRIPPED", "Local symbols removed (COFF)"],
  [0x0010, "AGGRESSIVE_WS_TRIM", "Aggressively trim working set (obsolete)"],
  [0x0020, "LARGE_ADDRESS_AWARE", "Image can handle >2GB addresses"],
  [0x0040, "BYTES_REVERSED_LO", "Little-endian byte ordering (obsolete)"],
  [0x0080, "32BIT_MACHINE", "Image is designed for a 32-bit machine"],
  [0x0100, "DEBUG_STRIPPED", "Debug info removed from file"],
  [0x0200, "REMOVABLE_RUN_FROM_SWAP", "Copy image to swap file if on removable media"],
  [0x0400, "NET_RUN_FROM_SWAP", "Copy image to swap file if on network"],
  [0x1000, "SYSTEM", "System file (kernel/driver)"],
  [0x2000, "DLL", "Dynamic-link library"],
  [0x4000, "UP_SYSTEM_ONLY", "Uni-processor machine only"],
  [0x8000, "BYTES_REVERSED_HI", "Big-endian byte ordering (obsolete)"]
];

export const DLL_FLAGS: OptionEntry[] = [
  [0x0020, "HIGH_ENTROPY_VA", "Indicates 64-bit high-entropy ASLR support (PE32+)"],
  [0x0040, "DYNAMIC_BASE", "Image is relocatable (ASLR)"],
  [0x0080, "FORCE_INTEGRITY", "Code integrity checks are enforced"],
  [0x0100, "NX_COMPAT", "Image is compatible with DEP (no-execute)"],
  [0x0200, "NO_ISOLATION", "Isolation disabled (no SxS)"],
  [0x0400, "NO_SEH", "No structured exception handling"],
  [0x0800, "NO_BIND", "Do not bind to import addresses"],
  [0x1000, "APPCONTAINER", "Must execute in AppContainer"],
  [0x2000, "WDM_DRIVER", "WDM driver"],
  [0x4000, "GUARD_CF", "Control Flow Guard enabled"],
  [0x8000, "TERMINAL_SERVER_AWARE", "Terminal Server aware"]
];

export const DD_NAMES = [
  "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE",
  "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "CLR_RUNTIME", "RESERVED"
];

export const DD_TIPS = {
  EXPORT: "Export directory: function addresses and names exported by the image.",
  IMPORT: "Import directory: modules and symbols that this image depends on (link-time).",
  RESOURCE: "Resource directory: version, icons, dialogs, manifests, etc.",
  EXCEPTION: "Exception directory (.pdata): unwind info for x64 structured exception handling.",
  SECURITY: "Security directory: WIN_CERTIFICATE / Authenticode signatures (not mapped into memory).",
  BASERELOC: "Base relocation directory (.reloc): fixups applied when image is not loaded at preferred base.",
  DEBUG: "Debug directory: CodeView/RSDS pointers to PDBs, misc debug info.",
  TLS: "Thread Local Storage: per-thread data and optional TLS callbacks.",
  LOAD_CONFIG: "Load Configuration: security hardening structures (CFG, SEH tables, GS cookie).",
  IAT: "Import Address Table: resolved addresses loaded by the loader (runtime).",
  DELAY_IMPORT: "Delay-load import descriptors (resolved on first use).",
  CLR_RUNTIME: ".NET/CLR header for managed assemblies."
} as const;

export const SEC_FLAG_TEXTS: OptionEntry[] = [
  [0x00000020, "CNT_CODE"],
  [0x00000040, "CNT_INITIALIZED_DATA"],
  [0x00000080, "CNT_UNINITIALIZED_DATA"],
  [0x02000000, "DISCARDABLE"],
  [0x04000000, "NOT_CACHED"],
  [0x08000000, "NOT_PAGED"],
  [0x10000000, "SHARED"],
  [0x20000000, "EXECUTE"],
  [0x40000000, "READ"],
  [0x80000000, "WRITE"]
];

export const GUARD_FLAGS: OptionEntry[] = [
  [0x00000100, "CF_INSTRUMENTED"],
  [0x00000200, "CFW_INSTRUMENTED"],
  [0x00000400, "CF_FUNCTION_TABLE_PRESENT"],
  [0x00000800, "SECURITY_COOKIE_UNUSED"],
  [0x00001000, "PROTECT_DELAYLOAD_IAT"],
  [0x00002000, "DELAYLOAD_IAT_IN_ITS_OWN_SECTION"],
  [0x00004000, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"],
  [0x00008000, "CF_ENABLE_EXPORT_SUPPRESSION"],
  [0x00010000, "CF_LONGJUMP_TABLE_PRESENT"],
  [0x00400000, "EH_CONTINUATION_TABLE_PRESENT"]
];
