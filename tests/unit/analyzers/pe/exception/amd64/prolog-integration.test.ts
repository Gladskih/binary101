import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../../../../../analyzers/pe/index.js";
import { parseAmd64ExceptionTable } from "../../../../../../analyzers/pe/exception/amd64/index.js";
import { createPePrologFile } from "../../../../../fixtures/pe-prolog-file.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import { legacyU32 } from "../../../../../fixtures/pe-legacy-codeview.js";

void test("ordinary PE parsing automatically checks prologs without a separate action", async () => {
  const parsed = await parsePe(createPePrologFile());
  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.equal(parsed.exception?.prologValidation?.matchedCount, 1);
  assert.equal(parsed.exception?.prologValidation?.findings.length, 1);
  assert.equal(parsed.exception?.prologValidation?.findings[0]?.beginRva, 0x1008);
  assert.deepEqual(parsed.exception?.issues, []);
});

void test("a failed disassembler leaves metadata available with visible incomplete coverage", async () => {
  const bytes = new Uint8Array(32);
  bytes[16] = 1;
  const parsed = await parseAmd64ExceptionTable(new MockFile(bytes),
    new MockFile(Uint8Array.from([4, 8, 16].flatMap(legacyU32))), 1, rva => rva, [],
    undefined, async () => { throw new Error("Unavailable WASM"); });
  assert.equal(parsed.functionCount, 1);
  assert.deepEqual(parsed.prologValidation?.unverifiedCounts, { "disassembler-unavailable": 1 });
  assert.deepEqual(parsed.issues, []);
});
