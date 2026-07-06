"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBinaryType, parseForUi } from "../../../../analyzers/index.js";
import { createCoffObjectBytes, createCoffObjectFile } from "../../../fixtures/coff-object-fixture.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("detectBinaryType recognises COFF object files", async () => {
  const label = await detectBinaryType(createCoffObjectFile());

  assert.strictEqual(label, "COFF object file for x86 (I386)");
});

void test("parseForUi routes COFF object files through standalone COFF analysis", async () => {
  const detection = await detectBinaryType(createCoffObjectFile());
  assert.strictEqual(detection, "COFF object file for x86 (I386)");

  const parsed = await parseForUi(createCoffObjectFile());

  assert.strictEqual(parsed.analyzer, "coff");
  if (parsed.analyzer !== "coff") assert.fail("expected COFF parse result");
  assert.strictEqual(parsed.parsed.signature, "COFF");
  assert.strictEqual(parsed.parsed.sections.length, 1);
  assert.strictEqual(parsed.parsed.relocations?.[0]?.records[0]?.symbolTableIndex, 2);
  // Microsoft PE/COFF: IMAGE_REL_I386_REL32 is the x86 rel32 relocation type.
  assert.strictEqual(parsed.parsed.relocations?.[0]?.records[0]?.type, 0x0014);
  assert.strictEqual(parsed.parsed.coffDebug?.symbols[0]?.name, ".file");
  assert.strictEqual(parsed.parsed.coffDebug?.symbols[1]?.name, "target");
  assert.deepStrictEqual(parsed.parsed.warnings ?? [], []);
});

void test("parseForUi keeps truncated COFF object symbol tables visible with warnings", async () => {
  const truncated = new MockFile(createCoffObjectBytes().slice(0, 80), "truncated.obj");

  const parsed = await parseForUi(truncated);

  assert.strictEqual(parsed.analyzer, "coff");
  if (parsed.analyzer !== "coff") assert.fail("expected COFF parse result");
  assert.strictEqual(parsed.parsed.signature, "COFF");
  assert.ok(parsed.parsed.coffDebug?.warnings?.some(warning => /truncated/i.test(warning)));
});
