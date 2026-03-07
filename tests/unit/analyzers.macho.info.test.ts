"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
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
} from "../../analyzers/macho/commands.js";
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

void test("Mach-O identity helpers decode known, fallback, and ptrauth CPU metadata", () => {
  assert.equal(cpuTypeName(0x01000007), "x86-64");
  assert.equal(cpuTypeName(0x12345678), "CPU 0x12345678");
  assert.equal(cpuSubtypeName(7, 3), "all");
  assert.equal(cpuSubtypeName(12, 9), "v7");
  assert.equal(cpuSubtypeName(0x0100000c, 0x02000002), "arm64e (ptrauth v2)");
  assert.equal(cpuSubtypeName(0x01000012, 100), "970");
  assert.equal(cpuSubtypeName(0x99, 1), null);
  assert.equal(fileTypeName(2), "Executable");
  assert.equal(fileTypeName(0xffff), null);
  assert.deepEqual(headerFlags(0x00210000), ["Binds to weak symbols", "PIE"]);
});

void test("Mach-O load-command info helpers cover switch cases and fallbacks", () => {
  assert.equal(loadCommandName(0x19), "LC_SEGMENT_64");
  assert.equal(loadCommandName(0xdead), "0xdead");
  assert.equal(loadCommandDescription(0x1d), "Code signing blob");
  assert.equal(loadCommandDescription(0xdead), null);
  assert.deepEqual(
    [
      LC_ID_DYLIB,
      LC_REEXPORT_DYLIB,
      LC_LOAD_WEAK_DYLIB,
      LC_LOAD_UPWARD_DYLIB,
      LC_LAZY_LOAD_DYLIB,
      0x0
    ].map(dylibCommandKind),
    ["Install name", "Re-export", "Weak load", "Upward load", "Lazy load", "Load"]
  );
  assert.deepEqual(
    [
      LC_VERSION_MIN_MACOSX,
      LC_VERSION_MIN_IPHONEOS,
      LC_VERSION_MIN_TVOS,
      LC_VERSION_MIN_WATCHOS,
      0x0
    ].map(versionMinTargetName),
    ["macOS", "iPhoneOS", "tvOS", "watchOS", "Unknown"]
  );
  assert.equal(platformName(11), "visionOS");
  assert.equal(platformName(0xff), null);
  assert.equal(buildToolName(3), "ld");
  assert.equal(buildToolName(0xff), null);
  assert.equal(symbolTypeName(0x0e), "Defined in section");
  assert.equal(symbolTypeName(0x06), "0x6");
  assert.equal(sectionTypeName(0x80000400), "Regular");
  assert.equal(sectionTypeName(0xff), "0xff");
  assert.deepEqual(sectionAttributeFlagNames(0xa0000400), ["Pure instructions", "Strip static symbols", "Some instructions"]);
  assert.deepEqual(vmProtectionNames(0x7), ["read", "write", "execute"]);
  assert.deepEqual(vmProtectionNames(0x0), []);
});

void test("buildTruncatedImage preserves available header fields for 32-bit and 64-bit headers", () => {
  const thin32Bytes = new Uint8Array(28);
  const thin32View = new DataView(thin32Bytes.buffer);
  thin32View.setUint32(0, 0xfeedface, false);
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
  thin64View.setUint32(0, 0xfeedfacf, false);
  thin64View.setUint32(4, 0x01000007, false);
  thin64View.setUint32(28, 0x55aa, false);
  const thin64Magic = getMachOMagicInfo(new DataView(thin64Bytes.buffer, 0, 4));
  assert.ok(thin64Magic);
  assert.equal(thin64Magic.kind, "thin");
  const thin64 = buildTruncatedImage(0, thin64Bytes.length, thin64View, thin64Magic, "short");
  assert.equal(thin64.header.cputype, 0x01000007);
  assert.equal(thin64.header.reserved, 0x55aa);
});
