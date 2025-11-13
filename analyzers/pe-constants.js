"use strict";

// PE constants used by parser and renderer
export const MACHINE = [
  [0x0000, "UNKNOWN"], [0x014c, "x86 (I386)"], [0x8664, "x86-64 (AMD64)"],
  [0x01c0, "ARM"], [0x01c4, "ARMv7 Thumb-2 (ARMNT)"], [0xaa64, "ARM64"], [0xa641, "ARM64EC"], [0xa64e, "ARM64X"],
  [0x0200, "IA-64"], [0x0166, "MIPS"], [0x0168, "MIPS16"], [0x01f0, "POWERPC"], [0x01f1, "POWERPCFP"],
  [0x9041, "M32R"], [0x01a2, "SH3"], [0x01a3, "SH3DSP"], [0x01a6, "SH4"], [0x01a8, "SH5"], [0x01c2, "ARMv7 (old)"],
  [0x0EBC, "EFI Byte Code"], [0x5032, "RISC-V32"], [0x5064, "RISC-V64"], [0x5128, "RISC-V128"]
];

export const SUBSYSTEMS = [
  [0, "Unknown"], [1, "Native"], [2, "Windows GUI"], [3, "Windows CUI"], [5, "OS/2 CUI"], [7, "POSIX CUI"],
  [9, "Windows CE GUI"], [10, "EFI Application"], [11, "EFI Boot Service Driver"], [12, "EFI Runtime Driver"],
  [13, "EFI ROM"], [14, "XBOX"], [16, "Windows Boot Application"]
];

export const CHAR_FLAGS = [
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
  [0x0800, "SYSTEM", "System file (kernel/driver)"],
  [0x1000, "DLL", "Dynamic-link library"],
  [0x2000, "UP_SYSTEM_ONLY", "Uni-processor machine only"],
  [0x8000, "BYTES_REVERSED_HI", "Big-endian byte ordering (obsolete)"],
];

export const DLL_FLAGS = [
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
  [0x8000, "TERMINAL_SERVER_AWARE", "Terminal Server aware"],
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
};

export const SEC_FLAG_TEXTS = [
  [0x00000020, "CNT_CODE"],
  [0x00000040, "CNT_INITIALIZED_DATA"],
  [0x00000080, "CNT_UNINITIALIZED_DATA"],
  [0x02000000, "DISCARDABLE"],
  [0x04000000, "NOT_CACHED"],
  [0x08000000, "NOT_PAGED"],
  [0x10000000, "SHARED"],
  [0x20000000, "EXECUTE"],
  [0x40000000, "READ"],
  [0x80000000, "WRITE"],
];

export const GUARD_FLAGS = [
  [0x00000100, "CF_INSTRUMENTED"],
  [0x00000200, "CF_WRITE_CHECKED"],
  [0x00000400, "CF_FUNCTION_TABLE_PRESENT"],
  [0x00000800, "SECURITY_COOKIE_UNUSED"],
  [0x00001000, "CF_LONGJUMP_TARGET"],
  [0x00004000, "CF_FUNCTION_TABLE_VALID"],
  [0x00008000, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"],
  [0x00010000, "CF_ENABLE_EXPORT_SUPPRESSION"],
  [0x00020000, "CF_LONGJUMP_TABLE_PRESENT"],
];

