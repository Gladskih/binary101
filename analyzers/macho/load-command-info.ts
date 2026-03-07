"use strict";

// Command IDs and structure semantics come from mach-o/loader.h in Apple's cctools/XNU sources:
// https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/loader.h

import {
  LC_ID_DYLIB,
  LC_LAZY_LOAD_DYLIB,
  LC_LOAD_UPWARD_DYLIB,
  LC_LOAD_WEAK_DYLIB,
  LC_REEXPORT_DYLIB,
  LC_VERSION_MIN_IPHONEOS,
  LC_VERSION_MIN_MACOSX,
  LC_VERSION_MIN_TVOS,
  LC_VERSION_MIN_WATCHOS
} from "./commands.js";

const loadCommandNames = new Map<number, [string, string | null]>([
  [0x1, ["LC_SEGMENT", "32-bit segment mapping"]],
  [0x2, ["LC_SYMTAB", "Symbol table"]],
  [0x4, ["LC_THREAD", "Thread state"]],
  [0x5, ["LC_UNIXTHREAD", "Unix thread state"]],
  [0xb, ["LC_DYSYMTAB", "Dynamic symbol table"]],
  [0xc, ["LC_LOAD_DYLIB", "Load dependent dynamic library"]],
  [0xd, ["LC_ID_DYLIB", "Install name for this dynamic library"]],
  [0xe, ["LC_LOAD_DYLINKER", "Load dynamic linker"]],
  [0xf, ["LC_ID_DYLINKER", "Dynamic linker identity"]],
  [0x80000018, ["LC_LOAD_WEAK_DYLIB", "Weakly loaded dynamic library"]],
  [0x19, ["LC_SEGMENT_64", "64-bit segment mapping"]],
  [0x1b, ["LC_UUID", "Binary UUID"]],
  [0x8000001c, ["LC_RPATH", "Runtime search path"]],
  [0x1d, ["LC_CODE_SIGNATURE", "Code signing blob"]],
  [0x8000001f, ["LC_REEXPORT_DYLIB", "Re-exported dynamic library"]],
  [0x20, ["LC_LAZY_LOAD_DYLIB", "Delay-loaded dynamic library"]],
  [0x21, ["LC_ENCRYPTION_INFO", "Encrypted range"]],
  [0x22, ["LC_DYLD_INFO", "Dyld compressed fixup info"]],
  [0x80000022, ["LC_DYLD_INFO_ONLY", "Dyld compressed fixup info only"]],
  [0x80000023, ["LC_LOAD_UPWARD_DYLIB", "Upward-loaded dynamic library"]],
  [0x24, ["LC_VERSION_MIN_MACOSX", "Minimum macOS version"]],
  [0x25, ["LC_VERSION_MIN_IPHONEOS", "Minimum iPhoneOS version"]],
  [0x26, ["LC_FUNCTION_STARTS", "Function starts table"]],
  [0x27, ["LC_DYLD_ENVIRONMENT", "Dyld environment string"]],
  [0x80000028, ["LC_MAIN", "Main entry point"]],
  [0x29, ["LC_DATA_IN_CODE", "Non-instruction ranges in code"]],
  [0x2a, ["LC_SOURCE_VERSION", "Source version"]],
  [0x2b, ["LC_DYLIB_CODE_SIGN_DRS", "Copied code-signing requirements"]],
  [0x2c, ["LC_ENCRYPTION_INFO_64", "Encrypted range (64-bit)"]],
  [0x2f, ["LC_VERSION_MIN_TVOS", "Minimum tvOS version"]],
  [0x30, ["LC_VERSION_MIN_WATCHOS", "Minimum watchOS version"]],
  [0x31, ["LC_NOTE", "Arbitrary note data"]],
  [0x32, ["LC_BUILD_VERSION", "Build platform and SDK metadata"]],
  [0x80000033, ["LC_DYLD_EXPORTS_TRIE", "Export trie"]],
  [0x80000034, ["LC_DYLD_CHAINED_FIXUPS", "Chained fixups"]],
  [0x80000035, ["LC_FILESET_ENTRY", "Fileset entry"]]
]);

const segmentFlagNames = new Map<number, string>([
  [0x1, "High VM"],
  [0x2, "Fixed-VM shared library"],
  [0x4, "No relocations"],
  [0x8, "Protected v1"],
  [0x10, "Read-only after fixups"]
]);

const sectionTypeNames = new Map<number, string>([
  [0x00, "Regular"],
  [0x01, "Zero-fill"],
  [0x02, "CString literals"],
  [0x03, "4-byte literals"],
  [0x04, "8-byte literals"],
  [0x05, "Literal pointers"],
  [0x06, "Non-lazy symbol pointers"],
  [0x07, "Lazy symbol pointers"],
  [0x08, "Symbol stubs"],
  [0x09, "Module init function pointers"],
  [0x0a, "Module term function pointers"],
  [0x0b, "Coalesced"],
  [0x0c, "GB zero-fill"],
  [0x0d, "Interposing"],
  [0x0e, "16-byte literals"],
  [0x0f, "DTrace DOF"],
  [0x10, "Lazy dylib symbol pointers"],
  [0x11, "Thread-local regular"],
  [0x12, "Thread-local zero-fill"],
  [0x13, "Thread-local variables"],
  [0x14, "Thread-local variable pointers"],
  [0x15, "Thread-local init function pointers"],
  [0x16, "Init function offsets"]
]);

const sectionAttributeNames = new Map<number, string>([
  [0x80000000, "Pure instructions"],
  [0x40000000, "No TOC"],
  [0x20000000, "Strip static symbols"],
  [0x10000000, "No dead strip"],
  [0x08000000, "Live support"],
  [0x04000000, "Self-modifying code"],
  [0x02000000, "Debug"],
  [0x00000400, "Some instructions"],
  [0x00000200, "External relocations"],
  [0x00000100, "Local relocations"]
]);

const platformNames = new Map<number, string>([
  [0, "Unknown"],
  [1, "macOS"],
  [2, "iOS"],
  [3, "tvOS"],
  [4, "watchOS"],
  [5, "bridgeOS"],
  [6, "Mac Catalyst"],
  [7, "iOS Simulator"],
  [8, "tvOS Simulator"],
  [9, "watchOS Simulator"],
  [10, "DriverKit"],
  [11, "visionOS"],
  [12, "visionOS Simulator"]
]);

const buildToolNames = new Map<number, string>([
  [1, "clang"],
  [2, "swift"],
  [3, "ld"],
  [4, "lld"],
  [1024, "metal"]
]);

const symbolTypeNames = new Map<number, string>([
  [0x0, "Undefined"],
  [0x2, "Absolute"],
  [0xa, "Indirect"],
  [0xc, "Prebound undefined"],
  [0xe, "Defined in section"]
]);

const collectFlagNames = (mask: number, names: Map<number, string>): string[] =>
  [...names.entries()]
    .filter(([bit]) => (mask & bit) !== 0)
    .map(([, name]) => name);

const sectionAttributesMask = [...sectionAttributeNames.keys()];

const loadCommandName = (cmd: number): string => loadCommandNames.get(cmd)?.[0] || `0x${cmd.toString(16)}`;
const loadCommandDescription = (cmd: number): string | null => loadCommandNames.get(cmd)?.[1] || null;
const dylibCommandKind = (cmd: number): string => {
  switch (cmd) {
    case LC_ID_DYLIB:
      return "Install name";
    case LC_REEXPORT_DYLIB:
      return "Re-export";
    case LC_LOAD_WEAK_DYLIB:
      return "Weak load";
    case LC_LOAD_UPWARD_DYLIB:
      return "Upward load";
    case LC_LAZY_LOAD_DYLIB:
      return "Lazy load";
    default:
      return "Load";
  }
};
const segmentFlags = (flags: number): string[] => collectFlagNames(flags, segmentFlagNames);
const vmProtectionNames = (prot: number): string[] => {
  const names: string[] = [];
  if ((prot & 0x1) !== 0) names.push("read");
  if ((prot & 0x2) !== 0) names.push("write");
  if ((prot & 0x4) !== 0) names.push("execute");
  return names;
};
const sectionTypeName = (flags: number): string =>
  sectionTypeNames.get(flags & 0xff) || `0x${(flags & 0xff).toString(16)}`;
const sectionAttributeFlagNames = (flags: number): string[] =>
  sectionAttributesMask.filter(bit => (flags & bit) !== 0).map(bit => sectionAttributeNames.get(bit) || "");
const versionMinTargetName = (cmd: number): string => {
  switch (cmd) {
    case LC_VERSION_MIN_MACOSX:
      return "macOS";
    case LC_VERSION_MIN_IPHONEOS:
      return "iPhoneOS";
    case LC_VERSION_MIN_TVOS:
      return "tvOS";
    case LC_VERSION_MIN_WATCHOS:
      return "watchOS";
    default:
      return "Unknown";
  }
};
const platformName = (platform: number): string | null => platformNames.get(platform) || null;
const buildToolName = (tool: number): string | null => buildToolNames.get(tool) || null;
const symbolTypeName = (type: number): string => symbolTypeNames.get(type & 0x0e) || `0x${(type & 0x0e).toString(16)}`;

export {
  buildToolName,
  dylibCommandKind,
  loadCommandDescription,
  loadCommandName,
  platformName,
  sectionAttributeFlagNames,
  sectionTypeName,
  segmentFlags,
  symbolTypeName,
  versionMinTargetName,
  vmProtectionNames
};
