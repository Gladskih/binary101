"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseGlobalPtrDirectory } from "../../analyzers/pe/directories/globalptr-directory.js";

// Microsoft PE format, "Optional Header Data Directories":
// GLOBALPTR.Size must be zero, so any non-zero value is intentionally malformed here.
const INVALID_GLOBALPTR_SIZE = 4;
// Distinct non-zero RVAs for these synthetic tests. The exact values are incidental;
// they only need to be non-zero and easy to distinguish in assertions.
const syntheticRva = (slot: number): number => 0x1000 + slot * 0x100;

const directory = (rva: number, size: number) => [{ name: "GLOBALPTR", rva, size }];

void test("parseGlobalPtrDirectory validates Size and RVA mapping", () => {
  assert.equal(parseGlobalPtrDirectory([], value => value), null);
  assert.equal(parseGlobalPtrDirectory(directory(0, 0), value => value), null);

  const valid = parseGlobalPtrDirectory(directory(syntheticRva(1), 0), value => value);
  assert.deepEqual(valid, { rva: syntheticRva(1), size: 0 });

  const malformed = parseGlobalPtrDirectory(
    directory(syntheticRva(32), INVALID_GLOBALPTR_SIZE),
    () => null
  );
  assert.ok(malformed);
  assert.ok(malformed.warnings?.some(warning => /size must be 0/i.test(warning)));
  assert.ok(malformed.warnings?.some(warning => /could not be mapped/i.test(warning)));
});

void test("parseGlobalPtrDirectory preserves a non-zero size with a missing RVA", () => {
  const result = parseGlobalPtrDirectory(directory(0, INVALID_GLOBALPTR_SIZE), value => value);

  assert.ok(result);
  assert.ok(result.warnings?.some(warning => /size must be 0/i.test(warning)));
  assert.ok(result.warnings?.some(warning => /RVA is 0/i.test(warning)));
});
