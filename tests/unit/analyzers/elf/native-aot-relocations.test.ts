"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { getElfRelativeArchitecture } from
  "../../../../analyzers/elf/native-aot-relocations.js";
import { createElf32Layout } from "../../../../analyzers/elf/elf32-layout.js";
import { createElf64Layout } from "../../../../analyzers/elf/elf64-layout.js";

void test("ELF NativeAOT relocation architecture recognizes supported little-endian targets", () => {
  assert.deepEqual(getElfRelativeArchitecture(62, createElf64Layout("little")), {
    pointerSize: 8,
    relocationType: 8
  });
  assert.deepEqual(getElfRelativeArchitecture(183, createElf64Layout("little")), {
    pointerSize: 8,
    relocationType: 1027
  });
});

void test("ELF NativeAOT relocation architecture rejects mismatched encodings", () => {
  assert.equal(getElfRelativeArchitecture(62, createElf32Layout("little")), null);
  assert.equal(getElfRelativeArchitecture(62, createElf64Layout("big")), null);
  assert.equal(getElfRelativeArchitecture(3, createElf32Layout("little")), null);
});
