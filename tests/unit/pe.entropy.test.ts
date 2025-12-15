"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addSectionEntropies } from "../../analyzers/pe/entropy.js";
import type { PeSection } from "../../analyzers/pe/types.js";
import { MockFile } from "../helpers/mock-file.js";

void test("addSectionEntropies scans full sections", async () => {
  const pointerToRawData = 0x200;
  const sizeOfRawData = 100000;
  const bytes = new Uint8Array(pointerToRawData + sizeOfRawData).fill(0);
  bytes.fill(0xff, pointerToRawData + sizeOfRawData / 2, pointerToRawData + sizeOfRawData);

  const file = new MockFile(bytes, "entropy.bin");
  const section: PeSection = {
    name: ".text",
    virtualSize: sizeOfRawData,
    virtualAddress: 0x1000,
    sizeOfRawData,
    pointerToRawData,
    characteristics: 0x60000020
  };

  await addSectionEntropies(file, [section]);
  assert.equal(section.entropy, 1);
});

void test("addSectionEntropies reports 0 when no raw data is present", async () => {
  const file = new MockFile(new Uint8Array([0]), "empty.bin");
  const section: PeSection = {
    name: ".bss",
    virtualSize: 0x100,
    virtualAddress: 0x1000,
    sizeOfRawData: 0,
    pointerToRawData: 0,
    characteristics: 0x40000000
  };

  await addSectionEntropies(file, [section]);
  assert.equal(section.entropy, 0);
});

void test("addSectionEntropies handles 1-byte sections", async () => {
  const pointerToRawData = 1;
  const sizeOfRawData = 1;
  const bytes = new Uint8Array([0, 0xff]);
  const file = new MockFile(bytes, "tiny.bin");
  const section: PeSection = {
    name: ".tiny",
    virtualSize: 1,
    virtualAddress: 0x1000,
    sizeOfRawData,
    pointerToRawData,
    characteristics: 0x40000000
  };

  await addSectionEntropies(file, [section]);
  assert.equal(section.entropy, 0);
});
