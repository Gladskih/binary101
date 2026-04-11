"use strict";

type DebugTypeInfo = { label: string; description: string };

// Microsoft PE format, "Debug Type":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
// LLVM COFF DebugType enum fills in additional toolchain-defined names such as
// VC_FEATURE / POGO / ILTCG / MPX:
// https://llvm.org/doxygen/namespacellvm_1_1COFF.html
const DEBUG_TYPE_INFOS: Record<number, DebugTypeInfo> = {
  0: { label: "UNKNOWN", description: "Unknown debug format ignored by tools." },
  1: {
    label: "COFF",
    description: "COFF line numbers, symbol table, and string table."
  },
  2: {
    label: "CODEVIEW",
    description: "Visual C++ debug information such as RSDS / PDB pointers."
  },
  3: {
    label: "FPO",
    description: "Frame-pointer omission metadata for nonstandard stack frames."
  },
  4: { label: "MISC", description: "Legacy location of a DBG file." },
  5: { label: "EXCEPTION", description: "Copy of the .pdata exception data." },
  6: { label: "FIXUP", description: "Reserved FIXUP debug type." },
  7: {
    label: "OMAP_TO_SRC",
    description: "Mapping from an RVA in the image to an RVA in the source image."
  },
  8: {
    label: "OMAP_FROM_SRC",
    description: "Mapping from an RVA in the source image to an RVA in the image."
  },
  9: { label: "BORLAND", description: "Reserved for Borland." },
  10: {
    label: "RESERVED10",
    description: "Reserved IMAGE_DEBUG_TYPE_RESERVED10 debug type."
  },
  11: { label: "CLSID", description: "Reserved CLSID debug type." },
  12: {
    label: "VC_FEATURE",
    description: "Visual C++ feature metadata emitted by the toolchain."
  },
  13: {
    label: "POGO",
    description: "Profile-guided optimization metadata emitted by the linker."
  },
  14: {
    label: "ILTCG",
    description: "Link-time code generation metadata emitted by the toolchain."
  },
  15: { label: "MPX", description: "Intel MPX metadata emitted by the toolchain." },
  16: { label: "REPRO", description: "PE determinism or reproducibility metadata." },
  17: {
    label: "EMBEDDED DEBUG",
    description: "Debugging information embedded in the PE file at PointerToRawData."
  },
  19: {
    label: "SYMBOL HASH",
    description: "Crypto hash of the symbol file content used to build the PE/COFF file."
  },
  20: {
    label: "EX_DLLCHARACTERISTICS",
    description: "Extended DLL characteristics bits beyond the optional-header field."
  }
};

export const getDebugTypeInfo = (type: number): DebugTypeInfo =>
  DEBUG_TYPE_INFOS[type] ?? {
    label: `TYPE_${type}`,
    description: `Undocumented or unsupported IMAGE_DEBUG_DIRECTORY.Type 0x${type.toString(16).padStart(8, "0")}.`
  };

