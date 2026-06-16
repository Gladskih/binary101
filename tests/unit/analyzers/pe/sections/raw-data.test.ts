"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addSectionRawDataAnalysis } from "../../../../../analyzers/pe/sections/raw-data.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import type { PeSection } from "../../../../../analyzers/pe/types.js";
import { MockFile } from "../../../../helpers/mock-file.js";

void test("addSectionRawDataAnalysis scans full sections for entropy", async () => {
  const pointerToRawData = 0x200;
  const sizeOfRawData = 100000;
  const bytes = new Uint8Array(pointerToRawData + sizeOfRawData).fill(0);
  bytes.fill(0xff, pointerToRawData + sizeOfRawData / 2, pointerToRawData + sizeOfRawData);

  const file = new MockFile(bytes, "entropy.bin");
  const section: PeSection = {
    name: inlinePeSectionName(".text"),
    virtualSize: sizeOfRawData,
    virtualAddress: 0x1000,
    sizeOfRawData,
    pointerToRawData,
    characteristics: 0x60000020
  };

  await addSectionRawDataAnalysis(file, [section]);
  assert.equal(section.entropy, 1);
});

void test("addSectionRawDataAnalysis reports zero-filled raw section tails", async () => {
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

  await addSectionRawDataAnalysis(file, [section]);
  assert.deepStrictEqual(section.rawTail, { zeroFilled: true, readableSize: 0x80 });
});

void test("addSectionRawDataAnalysis reports non-zero raw section tails", async () => {
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

  await addSectionRawDataAnalysis(file, [section]);
  assert.deepStrictEqual(section.rawTail, { zeroFilled: false, readableSize: 0x80 });
});

void test("addSectionRawDataAnalysis keeps truncated raw section tails explicit", async () => {
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

  await addSectionRawDataAnalysis(file, [section]);
  assert.deepStrictEqual(section.rawTail, {
    zeroFilled: null,
    readableSize: 0x40,
    warnings: ["Section raw tail is truncated by end of file; zero-fill status is incomplete."]
  });
});

void test("addSectionRawDataAnalysis omits rawTail when raw data does not exceed virtual size", async () => {
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

  await addSectionRawDataAnalysis(file, [section]);
  assert.equal(section.rawTail, undefined);
});

void test("addSectionRawDataAnalysis finds non-zero raw tails that start after the first chunk", async () => {
  // The production entropy scan chunks at 1 MiB; this fixture forces raw-tail detection into chunk 2.
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

  await addSectionRawDataAnalysis(file, [section]);
  assert.deepStrictEqual(section.rawTail, { zeroFilled: false, readableSize: 0x20 });
});

void test("addSectionRawDataAnalysis reports 0 entropy when no raw data is present", async () => {
  const file = new MockFile(new Uint8Array([0]), "empty.bin");
  const section: PeSection = {
    name: inlinePeSectionName(".bss"),
    virtualSize: 0x100,
    virtualAddress: 0x1000,
    sizeOfRawData: 0,
    pointerToRawData: 0,
    characteristics: 0x40000000
  };

  await addSectionRawDataAnalysis(file, [section]);
  assert.equal(section.entropy, 0);
});

void test("addSectionRawDataAnalysis handles 1-byte sections", async () => {
  const pointerToRawData = 1;
  const sizeOfRawData = 1;
  const bytes = new Uint8Array([0, 0xff]);
  const file = new MockFile(bytes, "tiny.bin");
  const section: PeSection = {
    name: inlinePeSectionName(".tiny"),
    virtualSize: 1,
    virtualAddress: 0x1000,
    sizeOfRawData,
    pointerToRawData,
    characteristics: 0x40000000
  };

  await addSectionRawDataAnalysis(file, [section]);
  assert.equal(section.entropy, 0);
});
