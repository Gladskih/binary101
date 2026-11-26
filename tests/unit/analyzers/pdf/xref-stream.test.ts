import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { parseIndirectDictionary } from "../../../../analyzers/pdf/object.js";
import { parseXrefStream } from "../../../../analyzers/pdf/xref-stream.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const read = async (fields: string, bytes: number[] = [], budget = 1) => {
  const header = "5 0 obj\n<< " + fields + " /Length " + bytes.length + " >>\nstream\n";
  const file = new File([header, Uint8Array.from(bytes), "\nendstream\nendobj"], "xref.pdf");
  const issues: string[] = [];
  const xref = await parseXrefStream(createFileRangeReader(file, 0, file.size),
    expectDefined(parseIndirectDictionary(header, 0)), 0, budget, issues);
  return { xref, issues };
};

void test("xref stream type must be anchored to the Type name", async () => {
  assert.deepEqual(await read("/Type /Other /Size 1 /W [1 1 1]"), { xref: null, issues: [] });
});

void test("xref stream honors all free-entry fields at the exact row budget", async () => {
  const result = await read("/Type /XRef /Size 6 /Index [0 1] /W [1 1 2]", [0, 5, 255, 255]);
  assert.deepEqual(result.xref?.entries, [{ objectNumber: 0, kind: "free", nextFree: 5, generation: 65535 }]);
  assert.deepEqual(result.issues, []);
});

for (const [fields, message] of [
  ["/Size 1 /W [1 1] /Index false", "invalid /Index array"],
  ["/Size 1 /W /Invalid", "invalid /W field widths"],
  ["/Size 1 /Index [/Invalid 1] /W [1 1 1]", "invalid /Index array"],
  ["/Size 1 /Index [0 1] /W [1 1 1]", "decoded byte count does not match the declared row layout"],
  ["/Size 1 /W [1 8388608 1]", "declared row layout exceeds the byte limit"]
] as const) {
  void test("retains the declared section but rejects invalid xref fields", async () => {
    const result = await read("/Type /XRef " + fields);
    assert.equal(result.xref?.entries, null);
    assert.deepEqual(result.issues, ["Cross-reference stream at 0: " + message + "."]);
  });
}
