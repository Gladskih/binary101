"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { getDebugTypeInfo } from "../../renderers/pe/debug-type-info.js";

void test("getDebugTypeInfo returns Microsoft PE metadata for CODEVIEW", () => {
  const info = getDebugTypeInfo(2); // IMAGE_DEBUG_TYPE_CODEVIEW in the PE spec.

  assert.deepEqual(info, {
    label: "CODEVIEW",
    description: "Visual C++ debug information such as RSDS / PDB pointers."
  });
});

void test("getDebugTypeInfo returns LLVM-backed toolchain metadata for POGO", () => {
  const info = getDebugTypeInfo(13); // IMAGE_DEBUG_TYPE_POGO in LLVM COFF debug type enum.

  assert.deepEqual(info, {
    label: "POGO",
    description: "Profile-guided optimization metadata emitted by the linker."
  });
});

void test("getDebugTypeInfo falls back for unknown debug types", () => {
  const info = getDebugTypeInfo(255);

  assert.deepEqual(info, {
    label: "TYPE_255",
    description: "Undocumented or unsupported IMAGE_DEBUG_DIRECTORY.Type 0x000000ff."
  });
});
