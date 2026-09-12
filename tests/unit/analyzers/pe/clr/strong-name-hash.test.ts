import assert from "node:assert/strict";
import { test } from "node:test";
import { buildStrongNameHashInput } from "../../../../../analyzers/pe/clr/strong-name-hash.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { makeStrongNamePeFixture, strongNameInputForFixture }
  from "../../../../helpers/pe-strong-name-fixture.js";

void test("strong-name hashing subtracts overlapping fragments without changing section order", async () => {
  const fixture = makeStrongNamePeFixture();
  const issues: string[] = [];
  assert.deepEqual(await buildStrongNameHashInput(new MockFile(fixture.bytes), [
    { start: fixture.layout.signatureOffset + 1, end: fixture.layout.signatureEnd },
    { start: fixture.layout.signatureOffset, end: fixture.layout.signatureOffset + 2 }
  ], issues), strongNameInputForFixture(fixture));
  assert.deepEqual(issues, []);
});

void test("strong-name hashing reports truncated DOS and PE headers", async () => {
  const fixture = makeStrongNamePeFixture();
  const issues: string[] = [];
  assert.equal(await buildStrongNameHashInput(new MockFile(fixture.bytes.subarray(0, 1)), [], issues), null);
  assert.match(issues.join(" "), /DOS header is truncated/);
  issues.length = 0;
  assert.equal(await buildStrongNameHashInput(new MockFile(
    fixture.bytes.subarray(0, fixture.layout.ntHeadersOffset)), [], issues), null);
  assert.match(issues.join(" "), /PE header offset is outside/);
});

void test("strong-name hashing rejects invalid PE signatures and optional header magic", async () => {
  const fixture = makeStrongNamePeFixture();
  const issues: string[] = [];
  fixture.bytes[fixture.layout.ntHeadersOffset] = 0;
  assert.equal(await buildStrongNameHashInput(new MockFile(fixture.bytes), [], issues), null);
  assert.match(issues.join(" "), /PE signature is missing/);
  fixture.bytes[fixture.layout.ntHeadersOffset] = 0x50; // Restore the P in PE\0\0.
  fixture.bytes[fixture.layout.optionalHeaderOffset] = 0;
  assert.equal(await buildStrongNameHashInput(new MockFile(fixture.bytes), [], issues), null);
  assert.match(issues.join(" "), /magic is unsupported/);
});

void test("strong-name hashing zeroes the checksum and security directory without modifying the file", async () => {
  const fixture = makeStrongNamePeFixture();
  const issues: string[] = [];
  fixture.bytes.fill(0xff,
    fixture.layout.optionalHeaderOffset + fixture.layout.checksumRelativeOffset,
    fixture.layout.optionalHeaderOffset + fixture.layout.checksumRelativeOffset + 4);
  fixture.bytes.fill(0xff,
    fixture.layout.dataDirectoriesOffset + fixture.layout.securityDirectoryIndex * fixture.layout.dataDirectorySize,
    fixture.layout.dataDirectoriesOffset +
      (fixture.layout.securityDirectoryIndex + 1) * fixture.layout.dataDirectorySize);
  const file = new MockFile(fixture.bytes);
  assert.deepEqual(await buildStrongNameHashInput(file, [{
    start: fixture.layout.signatureOffset, end: fixture.layout.signatureEnd
  }], issues), strongNameInputForFixture(fixture));
  assert.deepEqual(await file.readBytes(0, file.size), fixture.bytes);
  assert.deepEqual(issues, []);
});

void test("strong-name hashing ignores exclusions outside sections and can exclude an entire section", async () => {
  const fixture = makeStrongNamePeFixture();
  const issues: string[] = [];
  assert.deepEqual(await buildStrongNameHashInput(new MockFile(fixture.bytes), [
    { start: 0, end: 1 },
    { start: fixture.layout.fileSize, end: fixture.layout.fileSize + 1 }
  ], issues), Uint8Array.from([
    // IMAGE_SECTION_HEADER is 40 bytes. PE/COFF specification, Section Table.
    ...fixture.bytes.subarray(0, fixture.layout.sectionHeaderOffset + 40),
    ...fixture.bytes.subarray(fixture.layout.sectionRawPointer)
  ]));
  assert.deepEqual(await buildStrongNameHashInput(new MockFile(fixture.bytes), [
    { start: fixture.layout.sectionRawPointer, end: fixture.layout.fileSize }
  ], issues), fixture.bytes.subarray(0, fixture.layout.sectionHeaderOffset + 40));
  assert.deepEqual(issues, []);
});

for (const [label, end] of [
  ["optional header", makeStrongNamePeFixture().layout.optionalHeaderOffset],
  ["optional header", makeStrongNamePeFixture().layout.dataDirectoriesOffset - 1],
  ["data directories", makeStrongNamePeFixture().layout.sectionHeaderOffset - 1],
  ["section headers", makeStrongNamePeFixture().layout.sectionHeaderOffset + 1]
] as const) {
  void test(`strong-name hashing reports a truncated ${label} at ${end}`, async () => {
    const issues: string[] = [];
    assert.equal(await buildStrongNameHashInput(
      new MockFile(makeStrongNamePeFixture().bytes.subarray(0, end)), [], issues), null);
    assert.match(issues.join(" "), new RegExp(`PE ${label} is truncated`));
  });
}

void test("strong-name hashing reports a short section read", async context => {
  const fixture = makeStrongNamePeFixture();
  const file = new MockFile(fixture.bytes);
  const issues: string[] = [];
  context.mock.method(file, "readBytes", async (offset: number, size: number) =>
    fixture.bytes.subarray(offset,
      offset + size - Number(offset === fixture.layout.sectionRawPointer)));
  assert.equal(await buildStrongNameHashInput(file, [], issues), null);
  assert.match(issues.join(" "), /PE section data is truncated/);
});
