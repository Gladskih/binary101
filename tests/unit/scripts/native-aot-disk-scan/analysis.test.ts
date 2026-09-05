import assert from "node:assert/strict";
import { test } from "node:test";
import { scanNativeAotReader, scanNativeAotDiskFile } from
  "../../../../scripts/native-aot-disk-scan/analysis.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createPeWithSectionAndIat } from "../../../fixtures/sample-files-pe.js";

void test("native AOT reader scan ignores truncated and ordinary PE files", async () => {
  const ordinary = new MockFile(createPeWithSectionAndIat());

  assert.deepEqual(await scanNativeAotReader(new MockFile(new Uint8Array(0)), "empty", 0),
    { pe: false, match: null });
  assert.deepEqual(await scanNativeAotReader(ordinary, "ordinary", ordinary.size),
    { pe: true, match: null });
});

void test("native AOT disk scan closes a non-PE file and reports open failures", async () => {
  assert.deepEqual(await scanNativeAotDiskFile("package.json", 1), { pe: false, match: null });
  await assert.rejects(scanNativeAotDiskFile("package.json/missing", 1));
});
