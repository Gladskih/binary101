"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { getMachOMagicInfo } from "../../analyzers/macho/format.js";
import { parseFatBinary } from "../../analyzers/macho/fat.js";
import {
  CPU_SUBTYPE_X86_64_ALL,
  CPU_TYPE_X86_64,
  createThinMachOFixture
} from "../fixtures/macho-thin-sample.js";
import { createMachOUniversalLayout, wrapMachOBytes } from "../fixtures/macho-fixtures.js";
import { createMachOIncidentalValues } from "../fixtures/macho-incidental-values.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";

// mach-o/fat.h: FAT_MAGIC and FAT_MAGIC_64.
const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;

const fatArch32Offset = (index: number): number => 8 + index * 20;
const fatArch64Offset = (index: number): number => 8 + index * 32;

const writeFatMagic = (bytes: Uint8Array, magic: number): void => {
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(0, magic, false);
};

const writeFatHeader = (bytes: Uint8Array, magic: number, sliceCount: number): void => {
  // mach-o/fat.h: fat_header stores magic and nfat_arch as big-endian u32 values.
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  view.setUint32(0, magic, false);
  view.setUint32(4, sliceCount, false);
};

const readFatArch32 = (
  bytes: Uint8Array,
  entryOffset: number
): {
  cpuType: number;
  cpuSubtype: number;
  offset: number;
  size: number;
  align: number;
} => {
  // mach-o/fat.h: fat_arch stores cputype, cpusubtype, offset, size, align.
  const view = new DataView(bytes.buffer, bytes.byteOffset + entryOffset, 20);
  return {
    cpuType: view.getUint32(0, false),
    cpuSubtype: view.getUint32(4, false),
    offset: view.getUint32(8, false),
    size: view.getUint32(12, false),
    align: view.getUint32(16, false)
  };
};

const writeFatArch32 = (
  bytes: Uint8Array,
  entryOffset: number,
  entry: {
    cpuType: number;
    cpuSubtype: number;
    offset: number;
    size: number;
    align: number;
  }
): void => {
  // mach-o/fat.h: fat_arch stores cputype, cpusubtype, offset, size, align.
  const view = new DataView(bytes.buffer, bytes.byteOffset + entryOffset, 20);
  view.setUint32(0, entry.cpuType, false);
  view.setUint32(4, entry.cpuSubtype, false);
  view.setUint32(8, entry.offset, false);
  view.setUint32(12, entry.size, false);
  view.setUint32(16, entry.align, false);
};

const writeFatArch64 = (
  bytes: Uint8Array,
  entryOffset: number,
  entry: {
    cpuType: number;
    cpuSubtype: number;
    offset: bigint;
    size: bigint;
    align: number;
    reserved: number;
  }
): void => {
  // mach-o/fat.h: fat_arch_64 extends fat_arch with 64-bit offset/size and reserved.
  const view = new DataView(bytes.buffer, bytes.byteOffset + entryOffset, 32);
  view.setUint32(0, entry.cpuType, false);
  view.setUint32(4, entry.cpuSubtype, false);
  view.setBigUint64(8, entry.offset, false);
  view.setBigUint64(16, entry.size, false);
  view.setUint32(24, entry.align, false);
  view.setUint32(28, entry.reserved, false);
};

const fatMagicInfo = (bytes: Uint8Array) => {
  const magicInfo = getMachOMagicInfo(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  assert.ok(magicInfo);
  assert.equal(magicInfo.kind, "fat");
  return magicInfo;
};

void test("parseFatBinary reports truncated fat headers", async () => {
  const bytes = new Uint8Array(4);
  writeFatMagic(bytes, FAT_MAGIC);
  const parsed = await parseFatBinary(wrapMachOBytes(bytes, "fat-truncated"), fatMagicInfo(bytes));
  assert.equal(parsed.fatHeader, null);
  assert.match(parsed.issues[0] || "", /Fat header is truncated/);
});

void test("parseFatBinary reports missing architecture records", async () => {
  const bytes = new Uint8Array(8);
  writeFatHeader(bytes, FAT_MAGIC, 2);
  const parsed = await parseFatBinary(wrapMachOBytes(bytes, "fat-empty"), fatMagicInfo(bytes));
  assert.equal(parsed.slices.length, 0);
  assert.match(parsed.issues[0] || "", /declares 2 slices but only 0 architecture records fit/);
});

void test("parseFatBinary reports slices that extend past the file", async () => {
  const fixture = createMachOUniversalLayout();
  const bytes = fixture.bytes;
  const firstSlice = readFatArch32(bytes, fatArch32Offset(0));
  writeFatArch32(bytes, fatArch32Offset(0), { ...firstSlice, size: bytes.length });
  const parsed = await parseFatBinary(wrapMachOBytes(bytes, "fat-range"), fatMagicInfo(bytes));
  assert.match(parsed.slices[0]?.issues[0] || "", /extends beyond the file/);
});

void test("parseFatBinary reports slices without supported Mach-O payloads", async () => {
  const fixture = createMachOUniversalLayout();
  const bytes = fixture.bytes;
  const view = new DataView(bytes.buffer);
  view.setUint32(fixture.slice0Offset, 0, false);
  const parsed = await parseFatBinary(wrapMachOBytes(bytes, "fat-invalid-slice"), fatMagicInfo(bytes));
  assert.match(parsed.slices[0]?.issues[0] || "", /does not contain a supported Mach-O image/);
});

void test("parseFatBinary parses FAT_MAGIC_64 slice records", async () => {
  const values = createMachOIncidentalValues();
  const thin = createThinMachOFixture(
    CPU_TYPE_X86_64,
    CPU_SUBTYPE_X86_64_ALL,
    values.nextUint8(),
    values.nextLabel("com.example.binary101.fat64")
  ).bytes;
  const sliceOffset = 0x1000;
  const reserved = values.nextUint16();
  const bytes = new Uint8Array(sliceOffset + thin.length);
  writeFatHeader(bytes, FAT_MAGIC_64, 1);
  writeFatArch64(bytes, fatArch64Offset(0), {
    cpuType: CPU_TYPE_X86_64,
    cpuSubtype: CPU_SUBTYPE_X86_64_ALL,
    offset: BigInt(sliceOffset),
    size: BigInt(thin.length),
    align: 12,
    reserved
  });
  bytes.set(thin, sliceOffset);

  const parsed = await parseFatBinary(wrapMachOBytes(bytes, "fat64-valid"), fatMagicInfo(bytes));

  assert.equal(parsed.fatHeader?.is64, true);
  assert.equal(parsed.slices.length, 1);
  assert.equal(parsed.slices[0]?.offset, sliceOffset);
  assert.equal(parsed.slices[0]?.size, thin.length);
  assert.equal(parsed.slices[0]?.align, 12);
  assert.equal(parsed.slices[0]?.reserved, reserved);
  assert.equal(parsed.slices[0]?.image?.header.is64, true);
  assert.deepEqual(parsed.issues, []);
});

void test("parseFatBinary reads fat slice records incrementally", async () => {
  const bytes = new Uint8Array(0x10028);
  // Deliberately absurd slice count so the parser must cap reads to available records.
  writeFatHeader(bytes, FAT_MAGIC_64, 0xffffffff);
  const tracked = createSliceTrackingFile(bytes, bytes.length, "fat-incremental");

  const parsed = await parseFatBinary(tracked.file, fatMagicInfo(bytes));

  assert.equal(parsed.slices.length, Math.floor((bytes.length - 8) / 32));
  assert.ok(Math.max(...tracked.requests) < tracked.file.size);
});

void test("parseFatBinary reports slices that overlap the fat-arch table and violate alignment", async () => {
  const fixture = createMachOUniversalLayout();
  const bytes = fixture.bytes;
  const firstSlice = readFatArch32(bytes, fatArch32Offset(0));
  writeFatArch32(bytes, fatArch32Offset(0), {
    ...firstSlice,
    // fat_header plus two fat_arch records occupies 48 bytes in this fixture,
    // so moving the slice to four bytes before that boundary forces overlap.
    offset: fatArch32Offset(2) - 4,
    align: 12
  });

  const parsed = await parseFatBinary(wrapMachOBytes(bytes, "fat-table-overlap"), fatMagicInfo(bytes));

  assert.match(parsed.slices[0]?.issues.join("\n") || "", /overlaps the fat architecture table/i);
  assert.match(parsed.slices[0]?.issues.join("\n") || "", /not aligned to 2\^12 bytes/i);
});

void test("parseFatBinary reports overlapping slices", async () => {
  const fixture = createMachOUniversalLayout();
  const bytes = fixture.bytes;
  const firstSlice = readFatArch32(bytes, fatArch32Offset(0));
  const secondSlice = readFatArch32(bytes, fatArch32Offset(1));
  writeFatArch32(bytes, fatArch32Offset(1), {
    ...secondSlice,
    offset: firstSlice.offset + Math.max(1, Math.floor(firstSlice.size / 4))
  });

  const parsed = await parseFatBinary(wrapMachOBytes(bytes, "fat-overlap"), fatMagicInfo(bytes));

  assert.match(parsed.slices[1]?.issues.join("\n") || "", /overlaps slice 0/i);
});
