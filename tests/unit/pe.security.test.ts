"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSecurityDirectory } from "../../analyzers/pe/security.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const WIN_CERTIFICATE_HEADER_SIZE = 8;
const WIN_CERT_REVISION_2_0 = 0x0200;
const WIN_CERT_TYPE_X509 = 0x0001;
const WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002;

class RejectNegativeSliceFile extends MockFile {
  override slice(start?: number, end?: number, contentType?: string): Blob {
    if ((start ?? 0) < 0 || (end ?? 0) < 0) {
      throw new Error("negative slice");
    }
    return super.slice(start, end, contentType);
  }
}

class GuardedMockFile extends MockFile {
  readonly sliceCalls: Array<{ start: number; end: number }> = [];

  override slice(start?: number, end?: number, contentType?: string): Blob {
    const normalizedStart = start ?? 0;
    const normalizedEnd = end ?? this.size;
    this.sliceCalls.push({ start: normalizedStart, end: normalizedEnd });
    if (normalizedStart < 0 || normalizedEnd < 0) {
      throw new Error("negative slice offset");
    }
    // Each WIN_CERTIFICATE entry is at least the fixed 8-byte header, so a valid walk cannot need
    // more than file.size / 8 entry reads before terminating.
    if (this.sliceCalls.length > Math.ceil(this.size / WIN_CERTIFICATE_HEADER_SIZE) + 1) {
      throw new Error("possible infinite WIN_CERTIFICATE walk");
    }
    return super.slice(start, end, contentType);
  }
}

const writeWinCertificateHeader = (
  view: DataView,
  off: number,
  length: number,
  certificateType: number
): void => {
  view.setUint32(off + 0, length, true);
  view.setUint16(off + 4, WIN_CERT_REVISION_2_0, true);
  view.setUint16(off + 6, certificateType, true);
};

void test("parseSecurityDirectory walks WIN_CERTIFICATE entries", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const secOff = 0x100;
  const dv = new DataView(bytes.buffer);
  writeWinCertificateHeader(dv, secOff, 12, WIN_CERT_TYPE_PKCS_SIGNED_DATA);
  const second = secOff + 16;
  writeWinCertificateHeader(dv, second, 16, WIN_CERT_TYPE_PKCS_SIGNED_DATA);

  const dirs = [{ name: "SECURITY", rva: secOff, size: 40 }];
  const parsed = await parseSecurityDirectory(new MockFile(bytes, "sec.bin"), dirs);
  const sec = expectDefined(parsed);
  const firstCert = expectDefined(sec.certs[0]);

  assert.strictEqual(sec.count, 2);
  assert.strictEqual(sec.certs.length, 2);
  assert.strictEqual(firstCert.certificateType, WIN_CERT_TYPE_PKCS_SIGNED_DATA);
  assert.strictEqual(firstCert.typeName.includes("PKCS#7"), true);
  assert.ok(firstCert.authenticode);
});

void test("parseSecurityDirectory walks all certificates in the declared table", async () => {
  const certCount = 9;
  const secOff = 0x40;
  const bytes = new Uint8Array(secOff + certCount * WIN_CERTIFICATE_HEADER_SIZE).fill(0);
  const dv = new DataView(bytes.buffer);
  for (let index = 0; index < certCount; index += 1) {
    const off = secOff + index * WIN_CERTIFICATE_HEADER_SIZE;
    writeWinCertificateHeader(dv, off, WIN_CERTIFICATE_HEADER_SIZE, WIN_CERT_TYPE_X509);
  }

  const parsed = await parseSecurityDirectory(
    new MockFile(bytes, "sec-many.bin"),
    [{ name: "SECURITY", rva: secOff, size: certCount * WIN_CERTIFICATE_HEADER_SIZE }]
  );

  const sec = expectDefined(parsed);
  assert.strictEqual(sec.count, certCount);
  assert.strictEqual(sec.certs.length, certCount);
});

void test("parseSecurityDirectory reports corruption when rounded certificate sizes do not cover the table", async () => {
  const secOff = 0x80;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  // Microsoft PE format spec, attribute certificate table:
  // WIN_CERTIFICATE.dwLength is 8-byte aligned in the table walk, so 12-byte content rounds up to 16 bytes.
  writeWinCertificateHeader(dv, secOff, 12, WIN_CERT_TYPE_PKCS_SIGNED_DATA);

  const parsed = await parseSecurityDirectory(
    new MockFile(bytes, "sec-gap.bin"),
    [{ name: "SECURITY", rva: secOff, size: 40 }]
  );

  const sec = expectDefined(parsed);
  assert.strictEqual(sec.count, 1);
  assert.ok(sec.warnings?.some(warning => warning.toLowerCase().includes("corrupt")));
});

void test("parseSecurityDirectory preserves truncated directories as warnings instead of dropping them", async () => {
  const secOff = 0x40;
  // Fewer than 8 bytes are available at the declared table offset, so even the WIN_CERTIFICATE header is truncated.
  const bytes = new Uint8Array(secOff + 4).fill(0);

  const parsed = await parseSecurityDirectory(
    new MockFile(bytes, "sec-truncated.bin"),
    [{ name: "SECURITY", rva: secOff, size: WIN_CERTIFICATE_HEADER_SIZE }]
  );

  const sec = expectDefined(parsed);
  assert.strictEqual(sec.count, 0);
  assert.ok(sec.warnings?.some(warning => warning.toLowerCase().includes("truncated")));
});

void test("parseSecurityDirectory warns when the certificate table offset is not quadword aligned", async () => {
  const secOff = 0x40 + 1; // Intentionally misaligned by 1 byte; attribute certificate tables must start on an 8-byte boundary.
  const bytes = new Uint8Array(secOff + WIN_CERTIFICATE_HEADER_SIZE).fill(0);
  const dv = new DataView(bytes.buffer);
  // Microsoft PE format, attribute certificate table:
  // the certificate table entry is a file offset to a quadword-aligned table.
  writeWinCertificateHeader(dv, secOff, WIN_CERTIFICATE_HEADER_SIZE, WIN_CERT_TYPE_X509);

  const parsed = await parseSecurityDirectory(
    new MockFile(bytes, "sec-unaligned.bin"),
    [{ name: "SECURITY", rva: secOff, size: WIN_CERTIFICATE_HEADER_SIZE }]
  );

  const sec = expectDefined(parsed);
  assert.strictEqual(sec.count, 1);
  assert.ok(sec.warnings?.some(warning => /align/i.test(warning)));
});

void test("parseSecurityDirectory warns when WIN_CERTIFICATE.dwLength is not quadword aligned", async () => {
  const secOff = 0x40;
  const bytes = new Uint8Array(secOff + 16).fill(0);
  const dv = new DataView(bytes.buffer);
  // Microsoft PE format:
  // dwLength includes any padding required to keep each WIN_CERTIFICATE entry quadword aligned.
  writeWinCertificateHeader(dv, secOff, 12, WIN_CERT_TYPE_X509);

  const parsed = await parseSecurityDirectory(
    new MockFile(bytes, "sec-length-not-aligned.bin"),
    [{ name: "SECURITY", rva: secOff, size: 16 }]
  );

  const sec = expectDefined(parsed);
  assert.strictEqual(sec.count, 1);
  assert.ok(sec.warnings?.some(warning => /length|align/i.test(warning)));
});

void test("parseSecurityDirectory treats oversized WIN_CERTIFICATE lengths as invalid instead of walking backwards", async () => {
  const secOff = 0x40;
  const bytes = new Uint8Array(0x100).fill(0);
  const dv = new DataView(bytes.buffer);
  // Microsoft PE format: WIN_CERTIFICATE.dwLength is an unsigned 32-bit length rounded up to 8-byte alignment.
  dv.setUint32(secOff + 0, 0xfffffff8, true);
  dv.setUint16(secOff + 4, WIN_CERT_REVISION_2_0, true);
  dv.setUint16(secOff + 6, WIN_CERT_TYPE_X509, true);

  const file = new GuardedMockFile(bytes, "sec-overflow.bin");
  const parsed = await parseSecurityDirectory(file, [
    { name: "SECURITY", rva: secOff, size: WIN_CERTIFICATE_HEADER_SIZE }
  ]);

  const sec = expectDefined(parsed);
  assert.ok(sec.warnings?.some(warning => /length|truncated|corrupt|align/i.test(warning)));
  assert.ok(file.sliceCalls.every(call => call.start >= 0 && call.end >= 0));
});

void test("parseSecurityDirectory warns when the attribute certificate table is not at the end of the file", async () => {
  const secOff = 0x40;
  const bytes = new Uint8Array(secOff + WIN_CERTIFICATE_HEADER_SIZE + 8).fill(0);
  const dv = new DataView(bytes.buffer);
  writeWinCertificateHeader(dv, secOff, WIN_CERTIFICATE_HEADER_SIZE, WIN_CERT_TYPE_X509);

  const parsed = await parseSecurityDirectory(
    new MockFile(bytes, "sec-not-last.bin"),
    [{ name: "SECURITY", rva: secOff, size: WIN_CERTIFICATE_HEADER_SIZE }]
  );

  const sec = expectDefined(parsed);
  assert.strictEqual(sec.count, 1);
  assert.ok(sec.warnings?.some(warning => /end of file|last thing|after/i.test(warning)));
});

void test("parseSecurityDirectory does not treat debug bytes after certificates as a generic layout warning", async () => {
  const secOff = 0x40;
  const debugOff = secOff + WIN_CERTIFICATE_HEADER_SIZE;
  const bytes = new Uint8Array(debugOff + 8).fill(0);
  const dv = new DataView(bytes.buffer);
  writeWinCertificateHeader(dv, secOff, WIN_CERTIFICATE_HEADER_SIZE, WIN_CERT_TYPE_X509);

  const parsed = await parseSecurityDirectory(
    new MockFile(bytes, "sec-before-debug.bin"),
    [
      { name: "SECURITY", rva: secOff, size: WIN_CERTIFICATE_HEADER_SIZE },
      { name: "DEBUG", rva: debugOff, size: 8 }
    ]
  );

  const sec = expectDefined(parsed);
  assert.strictEqual(sec.count, 1);
  assert.ok(!sec.warnings?.some(warning => /bytes after the declared table/i.test(warning)));
});

void test("parseSecurityDirectory does not walk backwards when WIN_CERTIFICATE length overflows signed rounding", async () => {
  const secOff = 1;
  const bytes = new Uint8Array(0x40).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(secOff + 0, 0xfffffff8, true);
  dv.setUint16(secOff + 4, WIN_CERT_REVISION_2_0, true);
  dv.setUint16(secOff + 6, WIN_CERT_TYPE_X509, true);

  await assert.doesNotReject(async () => {
    const parsed = await parseSecurityDirectory(
      new RejectNegativeSliceFile(bytes, "sec-overflow-length.bin"),
      [{ name: "SECURITY", rva: secOff, size: WIN_CERTIFICATE_HEADER_SIZE * 2 }]
    );
    assert.ok(parsed);
    assert.ok(expectDefined(parsed).warnings?.length);
  });
});
