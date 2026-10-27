import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSehScopes } from "../../../../../analyzers/pe/msvc-eh/seh.js";
import { createEhImage } from "../../../../../analyzers/pe/msvc-eh/image.js";
import { createEhFixture } from "../../../../fixtures/pe-msvc-eh.js";

const scopeFixture = () => {
  const subject = createEhFixture();
  const rva = subject.builder.allocateData(36);
  subject.builder.patchUint32(rva, 0, 2);
  subject.builder.patchUint32(rva, 4, subject.beginRva);
  subject.builder.patchUint32(rva, 8, subject.beginRva + 4);
  subject.builder.patchUint32(rva, 12, 1); // CRT catch-all filter sentinel.
  subject.builder.patchUint32(rva, 16, subject.catchRva);
  subject.builder.patchUint32(rva, 20, subject.beginRva);
  subject.builder.patchUint32(rva, 24, subject.beginRva + 8);
  subject.builder.patchUint32(rva, 28, subject.catchRva); // finally handler: target=0.
  return { ...subject, rva };
};

void test("SEH validates catch-all and finally records without inventing filters", async () => {
  const subject = scopeFixture();
  const fixture = subject.builder.build();
  const scopes = await parseSehScopes(createEhImage(fixture.file, fixture.core), subject.rva);
  assert.equal(scopes?.length, 2);
  assert.equal(scopes?.[0]?.filterRva, 1);
  assert.equal(scopes?.[1]?.targetRva, 0);
});

for (const [field, value] of [[0, 0], [0, 0xffffffff], [8, 0x1000], [12, 0], [16, 0x2000], [28, 1]]) {
  void test(`SEH rejects invalid field ${field}=${value}`, async () => {
    const subject = scopeFixture();
    subject.builder.patchUint32(subject.rva, field!, value!);
    const fixture = subject.builder.build();
    assert.equal(await parseSehScopes(createEhImage(fixture.file, fixture.core), subject.rva), null);
  });
}

void test("SEH rejects an unmapped header", async () => {
  const subject = scopeFixture();
  const fixture = subject.builder.build();
  assert.equal(await parseSehScopes(createEhImage(fixture.file, fixture.core), 0xffffffff), null);
});

void test("SEH accepts a scope table ending exactly at the raw file boundary", async () => {
  const subject = scopeFixture();
  subject.builder.truncateAtRva(subject.rva + 36);
  const fixture = subject.builder.build();
  assert.equal((await parseSehScopes(createEhImage(fixture.file, fixture.core), subject.rva))?.length, 2);
});

void test("SEH scope ranges must be executable independently of their filter and target", async () => {
  const subject = scopeFixture();
  subject.builder.patchUint32(subject.rva, 4, subject.rva);
  subject.builder.patchUint32(subject.rva, 8, subject.rva + 4);
  const fixture = subject.builder.build();
  assert.equal(await parseSehScopes(createEhImage(fixture.file, fixture.core), subject.rva), null);
});
