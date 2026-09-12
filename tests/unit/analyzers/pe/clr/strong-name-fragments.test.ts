import assert from "node:assert/strict";
import { test } from "node:test";
import { parseStrongName } from "../../../../../analyzers/pe/clr/strong-name.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { makeFragmentedSignedFixture } from "../../../../helpers/pe-fragmented-strong-name.js";

void test("strong-name verification excludes every signature fragment", async () => {
  const fixture = await makeFragmentedSignedFixture();
  const result = await parseStrongName(new MockFile(fixture.bytes), fixture.mapping, fixture.clr);
  assert.equal(result.verification, "valid");
  assert.deepEqual(result.issues, []);
});

void test("strong-name hashing preserves section order when fragments run backwards in the file", async () => {
  const fixture = await makeFragmentedSignedFixture([1, 0]);
  const result = await parseStrongName(new MockFile(fixture.bytes), fixture.mapping, fixture.clr);
  assert.equal(result.verification, "valid");
  assert.deepEqual(result.issues, []);
});

void test("strong-name verification still rejects modified section data between physical fragments", async () => {
  const fixture = await makeFragmentedSignedFixture([1, 0]);
  const dataOffset = fixture.mapping(fixture.clr.StrongNameSignatureRVA - 1)!;
  fixture.bytes[dataOffset] = fixture.bytes[dataOffset]! ^ 1;
  assert.equal((await parseStrongName(
    new MockFile(fixture.bytes), fixture.mapping, fixture.clr
  )).verification, "invalid");
});

void test("strong-name verification cannot skip an unmapped signature byte", async () => {
  const fixture = await makeFragmentedSignedFixture();
  const result = await parseStrongName(new MockFile(fixture.bytes),
    rva => rva === fixture.clr.StrongNameSignatureRVA + fixture.clr.StrongNameSignatureSize / 2
      ? null : fixture.mapping(rva), fixture.clr);
  assert.equal(result.status, "truncated");
  assert.equal(result.verification, "unknown");
  assert.ok(result.issues.length);
});
