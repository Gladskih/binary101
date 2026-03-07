"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { N_TYPE, N_UNDF } from "../../analyzers/macho/commands.js";
import { resolveEntryVirtualAddress } from "../../analyzers/macho/format.js";
import { parseMachO } from "../../analyzers/macho/index.js";
import { createMachOFile, createMachOUniversalFile, wrapMachOBytes } from "../fixtures/macho-fixtures.js";

void test("parseMachO parses thin 64-bit Mach-O executables with symbols and code signing", async () => {
  const parsed = await parseMachO(createMachOFile());
  assert.ok(parsed);
  assert.equal(parsed.kind, "thin");
  assert.ok(parsed.image);
  assert.equal(parsed.image.header.is64, true);
  assert.equal(parsed.image.header.littleEndian, true);
  assert.equal(parsed.image.header.magic, 0xfeedfacf);
  assert.equal(parsed.image.header.cputype, 0x01000007);
  assert.equal(parsed.image.header.filetype, 0x2);
  assert.equal(parsed.image.entryPoint?.entryoff, 0x230n);
  const entryVaddr = parsed.image.entryPoint
    ? resolveEntryVirtualAddress(parsed.image.segments, parsed.image.entryPoint.entryoff)
    : null;
  assert.equal(entryVaddr, 0x100000230n);
  assert.equal(parsed.image.dylibs[0]?.name, "/usr/lib/libSystem.B.dylib");
  assert.equal(parsed.image.segments[0]?.sections[0]?.sectionName, "__text");
  assert.equal(parsed.image.symtab?.symbols.filter(symbol => (symbol.type & N_TYPE) === N_UNDF).length, 1);
  assert.equal(parsed.image.codeSignature?.codeDirectory?.identifier, "com.example.binary101");
});

void test("parseMachO parses universal Mach-O binaries and nested slices", async () => {
  const parsed = await parseMachO(createMachOUniversalFile());
  assert.ok(parsed);
  assert.equal(parsed.kind, "fat");
  assert.ok(parsed.fatHeader);
  assert.equal(parsed.slices.length, 2);
  assert.equal(parsed.slices[0]?.cputype, 0x01000007);
  assert.equal(parsed.slices[1]?.cputype, 0x0100000c);
  assert.equal(parsed.slices[1]?.cpusubtype, 2);
  assert.equal(parsed.slices[1]?.image?.codeSignature?.codeDirectory?.identifier, "com.example.binary101.arm64e");
});

void test("parseMachO keeps truncated thin headers visible as issues", async () => {
  const parsed = await parseMachO(wrapMachOBytes(new Uint8Array([0xfe, 0xed, 0xfa, 0xcf]), "truncated-macho"));
  assert.ok(parsed);
  assert.equal(parsed.kind, "thin");
  assert.ok(parsed.image);
  assert.equal(parsed.image.header.magic, 0xfeedfacf);
  assert.deepEqual(parsed.image.loadCommands, []);
  assert.match(parsed.image.issues[0] ?? "", /header is truncated/i);
});
