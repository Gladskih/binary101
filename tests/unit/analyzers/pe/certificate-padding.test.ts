"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readPeCertificateAlignmentPadding } from "../../../../analyzers/pe/certificate-padding.js";
import { parseSecurityDirectory } from "../../../../analyzers/pe/security/index.js";
import { createCertificatePaddingFixture } from "../../../fixtures/pe-certificate-padding.js";
import { MockFile } from "../../../helpers/mock-file.js";

// The fixture's known image ends at 116; the next quadword boundary is 120.
const gap = { start: 116, end: 120 };
const image = { start: 0, end: 116 };

void test("certificate padding requires a validated table and a known preceding boundary", async () => {
  const fixture = await createCertificatePaddingFixture();

  assert.deepEqual(await readPeCertificateAlignmentPadding(
    fixture.file, fixture.security, [gap], [image]
  ), gap);
});

for (const length of [1, 2, 3, 4, 5, 6, 7]) {
  void test(`certificate padding accepts exactly ${length} zero bytes to the next boundary`, async () => {
    const fixture = await createCertificatePaddingFixture(120 - length);
    const range = { start: 120 - length, end: 120 };

    assert.deepEqual(await readPeCertificateAlignmentPadding(
      fixture.file, fixture.security, [range], [{ start: 0, end: range.start }]
    ), range);
  });
}

for (const index of [116, 117, 118, 119]) {
  void test(`certificate padding rejects a nonzero byte at offset ${index}`, async () => {
    const fixture = await createCertificatePaddingFixture();
    fixture.bytes[index] = 1;

    assert.equal(await readPeCertificateAlignmentPadding(
      new MockFile(fixture.bytes), fixture.security, [gap], [image]
    ), null);
  });
}

for (const security of [null, undefined, { count: 0, certs: [] }]) {
  void test(`certificate padding rejects missing entries: ${JSON.stringify(security)}`, async () => {
    const fixture = await createCertificatePaddingFixture();

    assert.equal(await readPeCertificateAlignmentPadding(
      fixture.file, security, [gap], [image]
    ), null);
  });
}

for (const range of [{ start: 108, end: 120 }, { start: 120, end: 120 }, gap]) {
  void test(`certificate padding preserves an unanchored or excessive gap: ${range.start}`, async () => {
    const fixture = await createCertificatePaddingFixture();

    assert.equal(await readPeCertificateAlignmentPadding(
      fixture.file, fixture.security, [range], []
    ), null);
  });
}

void test("certificate padding rejects a full aligned block even with an anchor", async () => {
  const fixture = await createCertificatePaddingFixture();

  assert.equal(await readPeCertificateAlignmentPadding(
    fixture.file, fixture.security, [{ start: 112, end: 120 }], [{ start: 0, end: 112 }]
  ), null);
});

void test("certificate padding rejects an empty gap even at a known boundary", async () => {
  const fixture = await createCertificatePaddingFixture();

  assert.equal(await readPeCertificateAlignmentPadding(
    fixture.file, fixture.security, [{ start: 120, end: 120 }], [{ start: 0, end: 120 }]
  ), null);
});

void test("certificate padding requires the preceding structure to end at the gap", async () => {
  const fixture = await createCertificatePaddingFixture();

  assert.equal(await readPeCertificateAlignmentPadding(
    fixture.file, fixture.security, [gap], [{ start: 0, end: 112 }]
  ), null);
});

void test("certificate padding rechecks file bounds after parsing security", async () => {
  const fixture = await createCertificatePaddingFixture();

  assert.equal(await readPeCertificateAlignmentPadding(
    new MockFile(fixture.bytes.subarray(0, 120)), fixture.security, [gap], [image]
  ), null);
});

void test("certificate padding requires an aligned table even for an anchored gap", async () => {
  const fixture = await createCertificatePaddingFixture();
  assert.ok(fixture.security);
  fixture.security.certs[0]!.offset = 119;

  assert.equal(await readPeCertificateAlignmentPadding(
    fixture.file, fixture.security, [{ start: 116, end: 119 }], [image]
  ), null);
});

void test("certificate padding keeps an unrelated zero range", async () => {
  const fixture = await createCertificatePaddingFixture();

  assert.equal(await readPeCertificateAlignmentPadding(
    fixture.file, fixture.security, [{ start: 116, end: 119 }], [image]
  ), null);
});

void test("certificate padding rejects truncated reads", async context => {
  const fixture = await createCertificatePaddingFixture();
  context.mock.method(fixture.file, "read", async () => new DataView(new ArrayBuffer(3)));

  assert.equal(await readPeCertificateAlignmentPadding(
    fixture.file, fixture.security, [gap], [image]
  ), null);
});

for (const start of [0, -8, 119, 128, 136, NaN, Infinity]) {
  void test(`certificate padding rejects unusable table offsets: ${start}`, async () => {
    const fixture = await createCertificatePaddingFixture();
    assert.ok(fixture.security);
    fixture.security.certs[0]!.offset = start;

    assert.equal(await readPeCertificateAlignmentPadding(
      fixture.file, fixture.security, [gap], [image]
    ), null);
  });
}

void test("certificate padding rejects partially read certificate contents", async () => {
  const fixture = await createCertificatePaddingFixture();
  assert.ok(fixture.security);
  fixture.security.certs[0]!.availableBytes -= 1;

  assert.equal(await readPeCertificateAlignmentPadding(
    fixture.file, fixture.security, [gap], [image]
  ), null);
});

void test("certificate padding requires every certificate entry to have been read fully", async () => {
  const fixture = await createCertificatePaddingFixture();
  const bytes = new Uint8Array(fixture.bytes.length + 8);
  bytes.set(fixture.bytes);
  bytes.set(fixture.bytes.subarray(120), 128);
  const file = new MockFile(bytes);
  const security = await parseSecurityDirectory(file, [{ name: "SECURITY", rva: 120, size: 16 }]);
  assert.ok(security);
  security.certs[1]!.availableBytes -= 1;

  assert.equal(await readPeCertificateAlignmentPadding(file, security, [gap], [image]), null);
});

for (const length of [0, 7, 16]) {
  void test(`certificate padding preserves zeros when certificate length is malformed: ${length}`, async () => {
    const fixture = await createCertificatePaddingFixture();
    new DataView(fixture.bytes.buffer).setUint32(120, length, true);
    const file = new MockFile(fixture.bytes);
    const security = await parseSecurityDirectory(file, fixture.inputs.dataDirs);

    assert.equal(await readPeCertificateAlignmentPadding(file, security, [gap], [image]), null);
  });
}

void test("certificate padding rejects a truncated declared table", async () => {
  const fixture = await createCertificatePaddingFixture();
  const security = await parseSecurityDirectory(fixture.file, [{ name: "SECURITY", rva: 120, size: 16 }]);

  assert.equal(await readPeCertificateAlignmentPadding(fixture.file, security, [gap], [image]), null);
});
