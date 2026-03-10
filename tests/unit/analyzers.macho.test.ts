"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveEntryVirtualAddress } from "../../analyzers/macho/format.js";
import { parseMachO } from "../../analyzers/macho/index.js";
import { createMinimalJavaClassBytes } from "../fixtures/java-class-fixtures.js";
import {
  createMachOFile,
  createMachOUniversalFile,
  createTruncatedFatMachOBytes,
  wrapMachOBytes
} from "../fixtures/macho-fixtures.js";
import { MockFile } from "../helpers/mock-file.js";
import { CPU_SUBTYPE_ARM64E, CPU_TYPE_ARM64, CPU_TYPE_X86_64 } from "../fixtures/macho-thin-sample.js";

void test("parseMachO parses thin 64-bit Mach-O executables with symbols and code signing", async () => {
  const parsed = await parseMachO(createMachOFile());
  assert.ok(parsed);
  assert.equal(parsed.kind, "thin");
  assert.ok(parsed.image);
  assert.equal(parsed.image.header.is64, true);
  assert.equal(parsed.image.header.littleEndian, true);
  assert.equal(parsed.image.header.magic, 0xcffaedfe); // MH_CIGAM_64
  assert.equal(parsed.image.header.cputype, CPU_TYPE_X86_64);
  assert.equal(parsed.image.header.filetype, 0x2);
  assert.equal(parsed.image.entryPoint?.entryoff, 0x230n);
  const entryVaddr = parsed.image.entryPoint
    ? resolveEntryVirtualAddress(parsed.image.segments, parsed.image.entryPoint.entryoff)
    : null;
  assert.equal(entryVaddr, 0x100000230n);
  assert.equal(parsed.image.dylibs[0]?.name, "/usr/lib/libSystem.B.dylib");
  assert.equal(parsed.image.segments[0]?.sections[0]?.sectionName, "__text");
  // mach-o/nlist.h: undefined symbols have N_TYPE bits 0x0.
  assert.equal(parsed.image.symtab?.symbols.filter(symbol => (symbol.type & 0x0e) === 0x0).length, 1);
  assert.equal(parsed.image.codeSignature?.codeDirectory?.identifier, "com.example.binary101");
});

void test("parseMachO parses universal Mach-O binaries and nested slices", async () => {
  const parsed = await parseMachO(createMachOUniversalFile());
  assert.ok(parsed);
  assert.equal(parsed.kind, "fat");
  assert.ok(parsed.fatHeader);
  assert.equal(parsed.slices.length, 2);
  assert.equal(parsed.slices[0]?.cputype, CPU_TYPE_X86_64);
  assert.equal(parsed.slices[1]?.cputype, CPU_TYPE_ARM64);
  assert.equal(parsed.slices[1]?.cpusubtype, CPU_SUBTYPE_ARM64E);
  assert.equal(parsed.slices[1]?.image?.codeSignature?.codeDirectory?.identifier, "com.example.binary101.arm64e");
});

void test("parseMachO keeps truncated thin headers visible as issues", async () => {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, 0xfeedfacf, false); // MH_MAGIC_64
  const parsed = await parseMachO(wrapMachOBytes(bytes, "truncated-macho"));
  assert.ok(parsed);
  assert.equal(parsed.kind, "thin");
  assert.ok(parsed.image);
  assert.equal(parsed.image.header.magic, 0xfeedfacf);
  assert.deepEqual(parsed.image.loadCommands, []);
  assert.match(parsed.image.issues[0] ?? "", /header is truncated/i);
});

void test("parseMachO keeps truncated fat headers visible as issues", async () => {
  const bytes = createTruncatedFatMachOBytes();
  const parsed = await parseMachO(wrapMachOBytes(bytes, "truncated-fat"));
  assert.ok(parsed);
  assert.equal(parsed.kind, "fat");
  assert.equal(parsed.fatHeader, null);
  assert.match(parsed.issues[0] ?? "", /Fat header is truncated/i);
});

void test("parseMachO does not misclassify large fat binaries as Java class files", async () => {
  const sliceCount = 45;
  const headerSize = 8;
  const archSize = 20;
  const sliceSize = 4;
  const tableSize = headerSize + sliceCount * archSize;
  const bytes = new Uint8Array(tableSize + sliceCount * sliceSize);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0xcafebabe, false);
  view.setUint32(4, sliceCount, false);
  for (let index = 0; index < sliceCount; index += 1) {
    const recordOffset = headerSize + index * archSize;
    const sliceOffset = tableSize + index * sliceSize;
    // mach/machine.h: CPU_TYPE_X86_64 == 0x01000007.
    view.setUint32(recordOffset, CPU_TYPE_X86_64, false);
    view.setUint32(recordOffset + 4, 3, false);
    view.setUint32(recordOffset + 8, sliceOffset, false);
    view.setUint32(recordOffset + 12, sliceSize, false);
    view.setUint32(recordOffset + 16, 0, false);
    // mach-o/loader.h: MH_MAGIC_64 == 0xfeedfacf.
    view.setUint32(sliceOffset, 0xfeedfacf, false);
  }
  const parsed = await parseMachO(wrapMachOBytes(bytes, "fat-not-java"));
  assert.ok(parsed);
  assert.equal(parsed.kind, "fat");
  assert.equal(parsed.slices.length, sliceCount);
});

void test("parseMachO does not treat Java class files as Mach-O fat binaries", async () => {
  const parsed = await parseMachO(new MockFile(createMinimalJavaClassBytes()));

  assert.equal(parsed, null);
});
