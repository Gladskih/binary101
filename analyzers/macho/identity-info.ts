"use strict";

// CPU, subtype, file-type, and header-flag values are defined in mach-o/loader.h:
// https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/loader.h

const CPU_SUBTYPE_MASK = 0xff000000;
const CPU_SUBTYPE_ARM64_PTR_AUTH_MASK = 0x0f000000;

const cpuTypeNames = new Map<number, string>([
  [6, "Motorola 680x0"],
  [7, "x86"],
  [0x01000007, "x86-64"],
  [10, "MC98000"],
  [11, "HPPA"],
  [12, "ARM"],
  [0x0100000c, "ARM64"],
  [0x0200000c, "ARM64_32"],
  [13, "MC88000"],
  [14, "SPARC"],
  [15, "i860"],
  [18, "PowerPC"],
  [0x01000012, "PowerPC64"]
]);

const x86Subtypes = new Map<number, string>([
  [3, "all"],
  [4, "arch1"],
  [8, "Haswell"]
]);

const armSubtypes = new Map<number, string>([
  [0, "all"],
  [5, "v4t"],
  [6, "v6"],
  [7, "v5tej"],
  [8, "xscale"],
  [9, "v7"],
  [10, "v7f"],
  [11, "v7s"],
  [12, "v7k"],
  [13, "v8"]
]);

const arm64Subtypes = new Map<number, string>([
  [0, "all"],
  [1, "v8"],
  [2, "arm64e"]
]);

const powerPcSubtypes = new Map<number, string>([
  [0, "all"],
  [1, "601"],
  [2, "602"],
  [3, "603"],
  [4, "603e"],
  [5, "603ev"],
  [6, "604"],
  [7, "604e"],
  [8, "620"],
  [9, "750"],
  [10, "7400"],
  [11, "7450"],
  [100, "970"]
]);

const fileTypeNames = new Map<number, string>([
  [1, "Relocatable object"],
  [2, "Executable"],
  [3, "Fixed VM shared library"],
  [4, "Core file"],
  [5, "Preloaded executable"],
  [6, "Dynamic library"],
  [7, "Dynamic linker"],
  [8, "Bundle"],
  [9, "Dylib stub"],
  [10, "dSYM companion"],
  [11, "Kernel extension bundle"],
  [12, "Fileset"]
]);

const headerFlagNames = new Map<number, string>([
  [0x00000001, "No undefined references"],
  [0x00000004, "Input for dynamic linker"],
  [0x00000080, "Two-level namespace"],
  [0x00002000, "Subsections via symbols"],
  [0x00008000, "Weak definitions"],
  [0x00010000, "Binds to weak symbols"],
  [0x00200000, "PIE"],
  [0x00800000, "Has TLV descriptors"],
  [0x01000000, "No heap execution"],
  [0x02000000, "App extension safe"],
  [0x08000000, "Simulator support"],
  [0x80000000, "Dylib in shared cache"]
]);

const collectFlagNames = (mask: number, names: Map<number, string>): string[] =>
  [...names.entries()]
    .filter(([bit]) => (mask & bit) !== 0)
    .map(([, name]) => name);

const describeCpuSubtype = (cputype: number, cpusubtype: number): string | null => {
  const baseSubtype = cpusubtype & ~CPU_SUBTYPE_MASK;
  let text = (
    cputype === 7 || cputype === 0x01000007
      ? x86Subtypes.get(baseSubtype)
      : cputype === 12
        ? armSubtypes.get(baseSubtype)
        : cputype === 0x0100000c || cputype === 0x0200000c
          ? arm64Subtypes.get(baseSubtype)
          : cputype === 18 || cputype === 0x01000012
            ? powerPcSubtypes.get(baseSubtype)
            : undefined
  ) || null;
  if (cputype === 0x0100000c && baseSubtype === 2) {
    const ptrAuthVersion = (cpusubtype & CPU_SUBTYPE_ARM64_PTR_AUTH_MASK) >>> 24;
    if (ptrAuthVersion > 0) text = `${text || "arm64e"} (ptrauth v${ptrAuthVersion})`;
  }
  return text;
};

const cpuTypeName = (cputype: number): string => cpuTypeNames.get(cputype) || `CPU 0x${cputype.toString(16)}`;
const cpuSubtypeName = (cputype: number, cpusubtype: number): string | null =>
  describeCpuSubtype(cputype, cpusubtype) || null;
const fileTypeName = (filetype: number): string | null => fileTypeNames.get(filetype) || null;
const headerFlags = (flags: number): string[] => collectFlagNames(flags, headerFlagNames);

export { cpuSubtypeName, cpuTypeName, fileTypeName, headerFlags };
