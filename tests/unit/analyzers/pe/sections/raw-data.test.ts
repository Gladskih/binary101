"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { FileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { addSectionRawTailAnalysis } from "../../../../../analyzers/pe/sections/raw-data.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import type { PeSection } from "../../../../../analyzers/pe/types.js";
import { MockFile } from "../../../../helpers/mock-file.js";

void test("addSectionRawTailAnalysis reports zero-filled raw section tails", async () => {
  const bytes = new Uint8Array(0x400).fill(0);
  bytes.fill(0xaa, 0x100, 0x180);
  const file = new MockFile(bytes);
  const section: PeSection = {
    name: inlinePeSectionName(".text"),
    virtualSize: 0x80,
    virtualAddress: 0x1000,
    sizeOfRawData: 0x100,
    pointerToRawData: 0x100,
    characteristics: 0x60000020
  };

  await addSectionRawTailAnalysis(file, [section]);
  assert.deepStrictEqual(section.rawTail, { zeroFilled: true, readableSize: 0x80 });
  assert.equal(section.entropy, undefined);
});

void test("addSectionRawTailAnalysis reads only the raw tail", async () => {
  const reads: Array<{ offset: number; size: number }> = [];
  const reader: FileRangeReader = {
    size: 0x400,
    read: async () => new DataView(new ArrayBuffer(0)),
    readBytes: async (offset, size) => {
      reads.push({ offset, size });
      return new Uint8Array(size);
    }
  };
  const section: PeSection = {
    name: inlinePeSectionName(".text"),
    virtualSize: 0x80,
    virtualAddress: 0x1000,
    sizeOfRawData: 0x100,
    pointerToRawData: 0x100,
    characteristics: 0x60000020
  };

  await addSectionRawTailAnalysis(reader, [section]);

  assert.deepEqual(reads, [{ offset: 0x180, size: 0x80 }]);
});

void test("addSectionRawTailAnalysis does not read a tail that starts at EOF", async () => {
  const reads: Array<{ offset: number; size: number }> = [];
  const reader: FileRangeReader = {
    size: 0x180,
    read: async () => new DataView(new ArrayBuffer(0)),
    readBytes: async (offset, size) => {
      reads.push({ offset, size });
      return new Uint8Array(0);
    }
  };
  const section: PeSection = {
    name: inlinePeSectionName(".trunc"),
    virtualSize: 0x80,
    virtualAddress: 0x1000,
    sizeOfRawData: 0x100,
    pointerToRawData: 0x100,
    characteristics: 0x40000040
  };

  await addSectionRawTailAnalysis(reader, [section]);

  assert.deepEqual(reads, []);
  assert.equal(section.rawTail?.readableSize, 0);
  assert.equal(section.rawTail?.zeroFilled, null);
});

void test("addSectionRawTailAnalysis caps automatic scans of large zero-filled tails", async () => {
  const chunkBytes = 1024 * 1024;
  const reads: Array<{ offset: number; size: number }> = [];
  const reader: FileRangeReader = {
    size: 0x10 + chunkBytes + 2,
    read: async () => new DataView(new ArrayBuffer(0)),
    readBytes: async (offset, size) => {
      reads.push({ offset, size });
      return new Uint8Array(size);
    }
  };
  const section: PeSection = {
    name: inlinePeSectionName(".tail"),
    virtualSize: 0x10,
    virtualAddress: 0x1000,
    sizeOfRawData: 0x10 + chunkBytes + 2,
    pointerToRawData: 0,
    characteristics: 0x40000040
  };

  await addSectionRawTailAnalysis(reader, [section]);

  assert.deepEqual(reads, [{ offset: 0x10, size: chunkBytes }]);
  assert.deepEqual(section.rawTail, {
    zeroFilled: null,
    readableSize: chunkBytes + 2,
    warnings: ["Section raw tail exceeds the automatic 1 MiB zero-fill scan budget."]
  });
});

void test("addSectionRawTailAnalysis fully checks a tail at the scan budget", async () => {
  const scanBudgetBytes = 1024 * 1024;
  const file = new MockFile(new Uint8Array(scanBudgetBytes));
  const section: PeSection = {
    name: inlinePeSectionName(".tail"),
    virtualSize: 0,
    virtualAddress: 0x1000,
    sizeOfRawData: scanBudgetBytes,
    pointerToRawData: 0,
    characteristics: 0x40000040
  };

  await addSectionRawTailAnalysis(file, [section]);

  assert.deepEqual(section.rawTail, {
    zeroFilled: true,
    readableSize: scanBudgetBytes
  });
});

void test("addSectionRawTailAnalysis reports non-zero raw section tails", async () => {
  const bytes = new Uint8Array(0x400).fill(0);
  bytes[0x190] = 0x7f;
  const file = new MockFile(bytes);
  const section: PeSection = {
    name: inlinePeSectionName(".data"),
    virtualSize: 0x80,
    virtualAddress: 0x1000,
    sizeOfRawData: 0x100,
    pointerToRawData: 0x100,
    characteristics: 0xc0000040
  };

  await addSectionRawTailAnalysis(file, [section]);
  assert.deepStrictEqual(section.rawTail, { zeroFilled: false, readableSize: 0x80 });
});

void test("addSectionRawTailAnalysis keeps truncated raw section tails explicit", async () => {
  const bytes = new Uint8Array(0x1c0).fill(0);
  const file = new MockFile(bytes);
  const section: PeSection = {
    name: inlinePeSectionName(".trunc"),
    virtualSize: 0x80,
    virtualAddress: 0x1000,
    sizeOfRawData: 0x100,
    pointerToRawData: 0x100,
    characteristics: 0x40000040
  };

  await addSectionRawTailAnalysis(file, [section]);
  assert.deepStrictEqual(section.rawTail, {
    zeroFilled: null,
    readableSize: 0x40,
    warnings: ["Section raw tail is truncated by end of file; zero-fill status is incomplete."]
  });
});

void test("addSectionRawTailAnalysis omits rawTail when raw data does not exceed virtual size", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const file = new MockFile(bytes);
  const section: PeSection = {
    name: inlinePeSectionName(".same"),
    virtualSize: 0x100,
    virtualAddress: 0x1000,
    sizeOfRawData: 0x100,
    pointerToRawData: 0x100,
    characteristics: 0x40000040
  };

  await addSectionRawTailAnalysis(file, [section]);
  assert.equal(section.rawTail, undefined);
});

void test("addSectionRawTailAnalysis reads a tail after a large section body", async () => {
  const chunkBoundary = 1024 * 1024;
  const pointerToRawData = 0x10;
  const virtualSize = chunkBoundary + 0x10;
  const sizeOfRawData = virtualSize + 0x20;
  const bytes = new Uint8Array(pointerToRawData + sizeOfRawData).fill(0);
  bytes[pointerToRawData + virtualSize + 1] = 0x7f;
  const file = new MockFile(bytes);
  const section: PeSection = {
    name: inlinePeSectionName(".tail2"),
    virtualSize,
    virtualAddress: 0x1000,
    sizeOfRawData,
    pointerToRawData,
    characteristics: 0x40000040
  };

  await addSectionRawTailAnalysis(file, [section]);
  assert.deepStrictEqual(section.rawTail, { zeroFilled: false, readableSize: 0x20 });
});
