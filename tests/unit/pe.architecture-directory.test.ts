"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseArchitectureDirectory } from "../../analyzers/pe/directories/architecture-directory.js";

const directory = (rva: number, size: number) => [{ name: "ARCHITECTURE", rva, size }];

// Any non-zero pair is enough to trigger the reserved-slot anomaly path.
const syntheticRva = (): number => 0x1200;
const syntheticSize = (): number => 0x10;

void test("parseArchitectureDirectory ignores a zero reserved slot and preserves non-zero anomalies", () => {
  assert.equal(parseArchitectureDirectory([]), null);
  assert.equal(parseArchitectureDirectory(directory(0, 0)), null);

  const result = parseArchitectureDirectory(directory(syntheticRva(), syntheticSize()));

  assert.ok(result);
  assert.equal(result.rva, syntheticRva());
  assert.equal(result.size, syntheticSize());
  assert.ok(result.warnings?.some(warning => /reserved/i.test(warning)));
});
