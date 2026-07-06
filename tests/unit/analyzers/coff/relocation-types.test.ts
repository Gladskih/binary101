"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_ARM64,
  IMAGE_FILE_MACHINE_I386
} from "../../../../analyzers/coff/machine.js";
import { formatCoffRelocationType } from "../../../../analyzers/coff/relocation-types.js";

void test("formatCoffRelocationType labels machine-specific COFF relocation types", () => {
  // Relocation values below are the documented REL32 entries for each machine family.
  assert.equal(formatCoffRelocationType(IMAGE_FILE_MACHINE_I386, 0x0014), "IMAGE_REL_I386_REL32");
  assert.equal(formatCoffRelocationType(IMAGE_FILE_MACHINE_AMD64, 0x0004), "IMAGE_REL_AMD64_REL32");
  assert.equal(formatCoffRelocationType(IMAGE_FILE_MACHINE_ARM64, 0x0011), "IMAGE_REL_ARM64_REL32");
});

void test("formatCoffRelocationType keeps unknown types explicit", () => {
  // 0xffff and machine 0x9999 are outside the documented table covered by this formatter.
  assert.equal(formatCoffRelocationType(IMAGE_FILE_MACHINE_I386, 0xffff), "TYPE_0xffff");
  assert.equal(formatCoffRelocationType(0x9999, 0x0001), "TYPE_0x0001");
});
