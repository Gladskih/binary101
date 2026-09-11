import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfFileHeader, isSupportedElfIdent } from "../../../../analyzers/elf/file-header.js";
import { createElfFile } from "../../../fixtures/elf-sample-file.js";

void test("reads the file header independently of the header tables", async () => {
  const result = (await readElfFileHeader(createElfFile()))!;
  assert.equal(result.header.entry, 0x400000n);
  assert.deepEqual(result.sections, []);
  assert.deepEqual(result.programHeaders, []);
  assert.deepEqual(result.issues, []);
  assert.equal(isSupportedElfIdent(result.ident), true);
  assert.equal(isSupportedElfIdent({ ...result.ident, classByte: 0 }), false);
  assert.equal(isSupportedElfIdent({ ...result.ident, dataByte: 0 }), false);
});

void test("returns a diagnostic header for truncated ELF64 and rejects short non-ELF data", async () => {
  const bytes = new Uint8Array(await createElfFile().arrayBuffer());
  const short = await readElfFileHeader(new File([bytes.subarray(0, 52)], "truncated"));
  assert.match(short!.issues.join(" "), /header is truncated/);
  assert.equal(short!.header.ehsize, 0);
  assert.equal(await readElfFileHeader(new File([bytes.subarray(0, 16)], "ident")), null);
  bytes[0] = 0;
  assert.equal(await readElfFileHeader(new File([bytes], "bad-magic")), null);
});
