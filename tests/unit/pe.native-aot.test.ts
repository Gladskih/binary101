"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectNativeAotCandidate } from "../../analyzers/pe/native-aot.js";
import { coffStringTablePeSectionName, inlinePeSectionName } from "../../analyzers/pe/sections/name.js";
import type { PeSection } from "../../analyzers/pe/types.js";

const section = (name: string): PeSection => ({
  name: inlinePeSectionName(name),
  virtualSize: 0,
  virtualAddress: 0,
  sizeOfRawData: 0,
  pointerToRawData: 0,
  characteristics: 0
});

const longNameSection = (name: string): PeSection => ({
  ...section(name),
  name: coffStringTablePeSectionName(name, name.length)
});

const generatedExportName = (index: number): string => `export-${index.toString(36)}`;

void test("detectNativeAotCandidate detects DotNetRuntimeDebugHeader export evidence", () => {
  const parsed = detectNativeAotCandidate(true, { entries: [{ name: "DotNetRuntimeDebugHeader" }] }, []);

  assert.strictEqual(parsed?.status, "candidate");
  assert.deepStrictEqual(parsed.evidence, ["Export named DotNetRuntimeDebugHeader is present."]);
});

void test("detectNativeAotCandidate detects no-CLR section evidence conservatively", () => {
  const parsed = detectNativeAotCandidate(false, null, [section(".managed"), longNameSection(".hydrated")]);

  assert.strictEqual(parsed?.status, "candidate");
  assert.deepStrictEqual(parsed.evidence, [
    "No CLR directory is present and both .managed and .hydrated sections exist."
  ]);
  assert.match(parsed?.note ?? "", /not a guarantee/);
});

void test("detectNativeAotCandidate combines independent evidence", () => {
  const parsed = detectNativeAotCandidate(
    false,
    { entries: [{ name: "DotNetRuntimeDebugHeader" }] },
    [section(".managed"), longNameSection(".hydrated")]
  );

  assert.strictEqual(parsed?.status, "candidate");
  assert.strictEqual(parsed.evidence.length, 2);
});

void test("detectNativeAotCandidate ignores normal native PEs and incomplete section evidence", () => {
  assert.strictEqual(detectNativeAotCandidate(false, null, [section(".text"), section(".rdata")]), null);
  assert.strictEqual(detectNativeAotCandidate(false, null, [section(".managed")]), null);
  assert.strictEqual(detectNativeAotCandidate(false, null, [longNameSection(".hydrated")]), null);
});

void test("detectNativeAotCandidate ignores section evidence when CLR is present", () => {
  assert.strictEqual(detectNativeAotCandidate(true, null, [section(".managed"), section(".hydrated")]), null);
});

void test("detectNativeAotCandidate ignores missing and unrelated export names", () => {
  const parsed = detectNativeAotCandidate(false, { entries: [{ name: null }, { name: generatedExportName(0) }] }, []);

  assert.strictEqual(parsed, null);
});
