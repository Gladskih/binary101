"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { getElfRelativeArchitecture } from
  "../../../../analyzers/elf/native-aot-relocations.js";

void test("ELF NativeAOT relocation architecture recognizes supported little-endian targets", () => {
  assert.deepEqual(getElfRelativeArchitecture(62, true, true), {
    pointerSize: 8,
    relocationType: 8
  });
  assert.deepEqual(getElfRelativeArchitecture(183, true, true), {
    pointerSize: 8,
    relocationType: 1027
  });
});

void test("ELF NativeAOT relocation architecture rejects mismatched encodings", () => {
  assert.equal(getElfRelativeArchitecture(62, false, true), null);
  assert.equal(getElfRelativeArchitecture(62, true, false), null);
  assert.equal(getElfRelativeArchitecture(3, false, true), null);
});
