import assert from "node:assert/strict";
import { test } from "node:test";
import { parseAmd64ExceptionTable } from "../../../../../../analyzers/pe/exception/amd64/index.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import { legacyU32 } from "../../../../../fixtures/pe-legacy-codeview.js";

void test("AMD64 exception tables can be stored independently from their referenced image bytes", async () => {
  const bytes = new Uint8Array(32);
  bytes[16] = 1; // Version-1 UNWIND_INFO with no codes or handlers.
  const result = await parseAmd64ExceptionTable(new MockFile(bytes),
    new MockFile(Uint8Array.from([4, 8, 16].flatMap(legacyU32))), 1, rva => rva, []);

  assert.equal(result.functionCount, 1);
  assert.deepEqual(result.beginRvas, [4]);
  assert.equal(result.uniqueUnwindInfoCount, 1);
  assert.equal(result.invalidEntryCount, 0);
  assert.deepEqual(result.issues, []);
});

void test("AMD64 exception tables without complete rows retain empty-table and truncation diagnostics", async () => {
  const result = await parseAmd64ExceptionTable(new MockFile(new Uint8Array(32)),
    new MockFile(new Uint8Array(11)), 1, rva => rva, []);

  assert.equal(result.functionCount, 0);
  assert.equal(result.format, "amd64");
  assert.match(result.issues.join(" | "), /truncated/);
  assert.match(result.issues.join(" | "), /complete RUNTIME_FUNCTION/);
});
