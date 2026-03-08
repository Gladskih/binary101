"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { getMachOMagicInfo } from "../../analyzers/macho/format.js";
import { cpuSubtypeName, cpuTypeName, fileTypeName, headerFlags } from "../../analyzers/macho/identity-info.js";
import {
  buildToolName,
  dylibCommandKind,
  loadCommandDescription,
  loadCommandName,
  platformName,
  sectionAttributeFlagNames,
  sectionTypeName,
  symbolTypeName,
  versionMinTargetName,
  vmProtectionNames
} from "../../analyzers/macho/load-command-info.js";
import { buildTruncatedImage } from "../../analyzers/macho/truncated-image.js";
import { CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_ARM64, CPU_TYPE_X86_64 } from "../fixtures/macho-thin-sample.js";

void test("Mach-O identity helpers decode known, fallback, and ptrauth CPU metadata", () => {
  assert.equal(cpuTypeName(CPU_TYPE_X86_64), "x86-64");
  // Not present in cpuTypeNames.
  assert.equal(cpuTypeName(0x12345678), "CPU 0x12345678");
  assert.equal(cpuSubtypeName(7, CPU_SUBTYPE_X86_64_ALL), "all");
  assert.equal(cpuSubtypeName(12, 9), "v7");
  assert.equal(cpuSubtypeName(CPU_TYPE_ARM64, 0x02000000 | CPU_SUBTYPE_ARM64E), "arm64e (ptrauth v2)");
  assert.equal(cpuSubtypeName(0x01000012, 100), "970");
  assert.equal(cpuSubtypeName(0x99, 1), null);
  assert.equal(fileTypeName(2), "Executable");
  // fileTypeNames only contains the Mach-O MH_* values 1..12.
  assert.equal(fileTypeName(0xffff), null);
  assert.deepEqual(headerFlags(0x00210000), ["Binds to weak symbols", "PIE"]);
});

void test("Mach-O load-command info helpers cover switch cases and fallbacks", () => {
  assert.equal(loadCommandName(0x19), "LC_SEGMENT_64"); // mach-o/loader.h: LC_SEGMENT_64
  // Not present in loadCommandNames.
  assert.equal(loadCommandName(0xdead), "0xdead");
  assert.equal(loadCommandDescription(0x1d), "Code signing blob"); // LC_CODE_SIGNATURE
  assert.equal(loadCommandDescription(0xdead), null);
  assert.deepEqual(
    [
      0xd, // LC_ID_DYLIB
      0x8000001f, // LC_REEXPORT_DYLIB
      0x80000018, // LC_LOAD_WEAK_DYLIB
      0x80000023, // LC_LOAD_UPWARD_DYLIB
      0x20, // LC_LAZY_LOAD_DYLIB
      0x0
    ].map(dylibCommandKind),
    ["Install name", "Re-export", "Weak load", "Upward load", "Lazy load", "Load"]
  );
  assert.deepEqual(
    [
      0x24, // LC_VERSION_MIN_MACOSX
      0x25, // LC_VERSION_MIN_IPHONEOS
      0x2f, // LC_VERSION_MIN_TVOS
      0x30, // LC_VERSION_MIN_WATCHOS
      0x0
    ].map(versionMinTargetName),
    ["macOS", "iPhoneOS", "tvOS", "watchOS", "Unknown"]
  );
  assert.equal(platformName(11), "visionOS");
  // platformNames only defines the currently known platform IDs 0..12.
  assert.equal(platformName(0xff), null);
  assert.equal(buildToolName(3), "ld");
  // buildToolNames only defines 1..4 and 1024.
  assert.equal(buildToolName(0xff), null);
  assert.equal(symbolTypeName(0x0e), "Defined in section");
  assert.equal(symbolTypeName(0x06), "0x6");
  assert.equal(sectionTypeName(0x80000400), "Regular");
  // sectionTypeName uses the low byte; 0xff is not assigned in sectionTypeNames.
  assert.equal(sectionTypeName(0xff), "0xff");
  assert.deepEqual(sectionAttributeFlagNames(0xa0000400), ["Pure instructions", "Strip static symbols", "Some instructions"]);
  assert.deepEqual(vmProtectionNames(0x7), ["read", "write", "execute"]);
  assert.deepEqual(vmProtectionNames(0x0), []);
});

void test("buildTruncatedImage preserves available header fields for 32-bit and 64-bit headers", () => {
  const thin32Bytes = new Uint8Array(28);
  const thin32View = new DataView(thin32Bytes.buffer);
  thin32View.setUint32(0, 0xfeedface, false); // MH_MAGIC
  thin32View.setUint32(4, 7, false);
  thin32View.setUint32(8, 3, false);
  thin32View.setUint32(12, 2, false);
  const thin32Magic = getMachOMagicInfo(new DataView(thin32Bytes.buffer, 0, 4));
  assert.ok(thin32Magic);
  assert.equal(thin32Magic.kind, "thin");
  const thin32 = buildTruncatedImage(0x10, thin32Bytes.length, thin32View, thin32Magic, "truncated");
  assert.equal(thin32.header.cputype, 7);
  assert.equal(thin32.header.filetype, 2);
  assert.equal(thin32.header.reserved, null);
  assert.deepEqual(thin32.issues, ["truncated"]);

  const thin64Bytes = new Uint8Array(32);
  const thin64View = new DataView(thin64Bytes.buffer);
  thin64View.setUint32(0, 0xcffaedfe, false); // MH_CIGAM_64
  thin64View.setUint32(4, CPU_TYPE_X86_64, true);
  thin64View.setUint32(28, 0x55aa, true);
  const thin64Magic = getMachOMagicInfo(new DataView(thin64Bytes.buffer, 0, 4));
  assert.ok(thin64Magic);
  assert.equal(thin64Magic.kind, "thin");
  const thin64 = buildTruncatedImage(0, thin64Bytes.length, thin64View, thin64Magic, "short");
  assert.equal(thin64.header.magic, 0xcffaedfe);
  assert.equal(thin64.header.cputype, CPU_TYPE_X86_64);
  assert.equal(thin64.header.reserved, 0x55aa);
});
