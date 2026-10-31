import assert from "node:assert/strict";
import { test } from "node:test";
import { rccNameHash, readRccName } from "../../../../analyzers/embedded-resources/rcc-names.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { minimalRcc, overwriteResource } from "../../../fixtures/embedded-resource-builders.js";

void test("implements the stable Qt resource hash including high-bit folding", () => {
  assert.equal(rccNameHash(""), 0);
  assert.equal(rccNameHash("a"), 97);
  assert.equal(rccNameHash("😀"), 942544); // Resource hashing uses both UTF-16 code units.
  assert.equal(rccNameHash("org"), 30343);
  // Independent expected hashes stored by Qt 5 rcc in oracle-v1.rcc.
  assert.equal(rccNameHash("binary101"), 76092977);
  assert.equal(rccNameHash("message.txt"), 120835796);
});

void test("reads a bounded UTF-16BE name and rejects invalid UTF-16 and NUL", async () => {
  const fixture = minimalRcc();
  assert.deepEqual(await readRccName(new MockFile(fixture.bytes),
    { offset: fixture.names, size: 8 }, 0), { name: "a", hash: 97 });
  const invalid = overwriteResource(fixture.bytes, fixture.names + 6, 0xd800, "be16");
  await assert.rejects(readRccName(new MockFile(invalid), { offset: fixture.names, size: 8 }, 0), /encoded data/);
  const nul = overwriteResource(fixture.bytes, fixture.names + 6, 0, "be16");
  await assert.rejects(readRccName(new MockFile(nul), { offset: fixture.names, size: 8 }, 0), /component/);
});

void test("preserves a leading U+FEFF in a length-delimited Qt name", async () => {
  const fixture = minimalRcc();
  const bytes = overwriteResource(overwriteResource(fixture.bytes, fixture.names + 6, 0xfeff, "be16"),
    fixture.names + 2, 0xfeff, "be32");
  assert.deepEqual(await readRccName(new MockFile(bytes), { offset: fixture.names, size: 8 }, 0),
    { name: "\ufeff", hash: 65279 });
});
