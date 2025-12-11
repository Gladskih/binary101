"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodePkcs7, decodeWinCertificate } from "../../analyzers/pe/authenticode.js";

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

const encodeLength = (len: number): Uint8Array => {
  if (len < 0x80) return Uint8Array.of(len);
  const bytes: number[] = [];
  let value = len;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>= 8;
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
};

const tag = (tagByte: number, content: Uint8Array): Uint8Array =>
  concat(Uint8Array.of(tagByte), encodeLength(content.length), content);

const seq = (...parts: Uint8Array[]): Uint8Array => tag(0x30, concat(...parts));
const set = (...parts: Uint8Array[]): Uint8Array => tag(0x31, concat(...parts));
const ctx0 = (content: Uint8Array): Uint8Array => tag(0xa0, content);

const oid = (value: string): Uint8Array => {
  const parts = value.split(".").map(Number);
  const first = (parts[0] ?? 0) * 40 + (parts[1] ?? 0);
  const body: number[] = [first];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i] ?? 0;
    const stack: number[] = [];
    stack.push(v & 0x7f);
    while ((v >>= 7) > 0) stack.unshift(0x80 | (v & 0x7f));
    body.push(...stack);
  }
  return tag(0x06, Uint8Array.from(body));
};

const int = (value: number): Uint8Array => {
  const bytes: number[] = [];
  let v = value;
  while (bytes.length === 0 || v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  const firstByte = bytes[0] ?? 0;
  if (firstByte & 0x80) bytes.unshift(0);
  return tag(0x02, Uint8Array.from(bytes));
};

const nul = (): Uint8Array => tag(0x05, new Uint8Array(0));
const octet = (bytes: Uint8Array): Uint8Array => tag(0x04, bytes);

const buildSignedData = (): Uint8Array => {
  const digestAlgorithm = seq(oid("2.16.840.1.101.3.4.2.1"), nul());
  const signedContent = seq(oid("1.3.6.1.4.1.311.2.1.4"), ctx0(octet(Uint8Array.of(0x00))));
  const paddedCert = octet(new Uint8Array(130).fill(0xaa));
  const certificates = ctx0(set(seq(int(1), paddedCert), seq(int(2))));
  const signerInfo = seq(
    int(1),
    seq(int(1), int(2)),
    seq(oid("1.3.14.3.2.26"), nul()),
    seq(oid("1.2.840.113549.1.1.1"), nul()),
    octet(Uint8Array.of(0x00))
  );
  const signerInfos = set(signerInfo);
  return seq(int(1), set(digestAlgorithm), signedContent, certificates, signerInfos);
};

const buildSignedDataCustom = (digestOid: string, contentOid: string, includeCrl = false): Uint8Array => {
  const digestAlgorithm = seq(oid(digestOid), nul());
  const signedContent = seq(oid(contentOid));
  const certificates = ctx0(set(seq(int(7))));
  const signerInfo = seq(
    int(1),
    seq(int(1), int(1)),
    seq(oid(digestOid), nul()),
    seq(oid("1.2.840.113549.1.1.1"), nul()),
    octet(Uint8Array.of(0x00))
  );
  const parts: Uint8Array[] = [int(1), set(digestAlgorithm), signedContent, certificates];
  if (includeCrl) {
    parts.push(tag(0xa1, new Uint8Array(0)));
  }
  parts.push(set(signerInfo));
  return seq(...parts);
};

void test("decodeWinCertificate extracts SignedData algorithms and counts", () => {
  const signedData = buildSignedData();
  const contentInfo = seq(oid("1.2.840.113549.1.7.2"), ctx0(signedData));
  const declaredLength = contentInfo.length + 8;
  const certBytes = new Uint8Array((declaredLength + 7) & ~7);
  const header = new DataView(certBytes.buffer, certBytes.byteOffset, certBytes.byteLength);
  header.setUint32(0, declaredLength, true);
  header.setUint16(4, 0x0200, true);
  header.setUint16(6, 0x0002, true);
  certBytes.set(contentInfo, 8);

  const decoded = decodeWinCertificate(certBytes.subarray(0, declaredLength), declaredLength, 0);
  assert.strictEqual(decoded.certificateType, 0x0002);
  assert.strictEqual(decoded.typeName.includes("SignedData"), true);
  const auth = decoded.authenticode;
  assert.ok(auth);
  assert.strictEqual(auth?.contentTypeName, "PKCS#7 signedData");
  assert.strictEqual(auth?.payloadContentTypeName, "SPC_INDIRECT_DATA");
  assert.ok(auth?.digestAlgorithms?.includes("sha256"));
  assert.strictEqual(auth?.signerCount, 1);
  assert.strictEqual(auth?.certificateCount, 2);
  assert.ok(!decoded.warnings);
});

void test("decodeWinCertificate flags truncated signature payload", () => {
  const payload = Uint8Array.of(0, 1, 2, 3);
  const declaredLength = payload.length + 8 + 8;
  const certBytes = new Uint8Array(payload.length + 8);
  const header = new DataView(certBytes.buffer);
  header.setUint32(0, declaredLength, true);
  header.setUint16(4, 0x0200, true);
  header.setUint16(6, 0x0002, true);
  certBytes.set(payload, 8);

  const decoded = decodeWinCertificate(certBytes, declaredLength, 0x80);
  assert.ok(decoded.warnings?.some(w => w.includes("truncated")));
  assert.ok(decoded.authenticode?.warnings?.length);
  assert.strictEqual(decoded.offset, 0x80);
});

void test("decodePkcs7 reports non-signed content types", () => {
  const dataContent = seq(oid("1.2.840.113549.1.7.1"), ctx0(octet(Uint8Array.of(1, 2))));
  const decoded = decodePkcs7(dataContent);
  assert.strictEqual(decoded.contentTypeName, "PKCS#7 data");
  assert.ok(decoded.warnings?.some(w => w.includes("not SignedData")));
  assert.strictEqual(decoded.signerCount, undefined);
});

void test("decodePkcs7 handles missing SignedData payload", () => {
  const missingPayload = seq(oid("1.2.840.113549.1.7.2"));
  const decoded = decodePkcs7(missingPayload);
  assert.ok(decoded.warnings?.some(w => w.includes("payload")));
  assert.strictEqual(decoded.digestAlgorithms, undefined);
});

void test("decodePkcs7 warns when digest algorithms set is empty", () => {
  const emptySignedData = seq(
    int(1),
    set(),
    seq(oid("1.3.6.1.4.1.311.2.1.4")),
    set()
  );
  const wrapper = seq(oid("1.2.840.113549.1.7.2"), ctx0(emptySignedData));
  const decoded = decodePkcs7(wrapper);
  assert.ok(decoded.warnings?.some(w => w.includes("digest")));
  assert.strictEqual(decoded.signerCount, 0);
});

void test("decodePkcs7 keeps unknown OIDs and optional CRLs", () => {
  const signedData = buildSignedDataCustom("1.2.3.4.5", "1.2.3.4.6", true);
  const wrapper = seq(oid("1.2.840.113549.1.7.2"), ctx0(signedData));
  const decoded = decodePkcs7(wrapper);
  assert.ok(decoded.digestAlgorithms?.includes("1.2.3.4.5"));
  assert.strictEqual(decoded.payloadContentType, "1.2.3.4.6");
  assert.ok(decoded.signerCount);
});

void test("decodePkcs7 treats overlong lengths as malformed", () => {
  const overrun = Uint8Array.of(0x30, 0x10, 0x06, 0x01);
  const decoded = decodePkcs7(overrun);
  assert.ok(decoded.warnings?.some(w => w.includes("DER")));
});

void test("decodeWinCertificate surfaces length mismatches", () => {
  const headerOnly = new Uint8Array(12);
  const view = new DataView(headerOnly.buffer);
  view.setUint32(0, 16, true);
  view.setUint16(4, 0x0100, true);
  view.setUint16(6, 0x0001, true);
  const decoded = decodeWinCertificate(headerOnly, 12, 0x10);
  assert.ok(decoded.warnings?.some(w => w.includes("Length field")));
  assert.strictEqual(decoded.typeName.includes("X.509"), true);
});

void test("decodeWinCertificate reports fallback names for unknown type and revision", () => {
  const data = new Uint8Array(12);
  const view = new DataView(data.buffer);
  view.setUint32(0, 12, true);
  view.setUint16(4, 0x0301, true);
  view.setUint16(6, 0xf00d, true);
  const decoded = decodeWinCertificate(data, 12, 0);
  assert.ok(decoded.revisionName.includes("0x0301"));
  assert.ok(decoded.typeName.includes("0xf00d"));
});

void test("decodePkcs7 warns on empty blobs", () => {
  const decoded = decodePkcs7(new Uint8Array());
  assert.ok(decoded.warnings?.some(w => w.includes("DER encoded")));
});

void test("decodePkcs7 flags single-byte blobs missing a length", () => {
  const decoded = decodePkcs7(Uint8Array.of(0x30));
  assert.ok(decoded.warnings?.some(w => w.includes("DER encoded")));
});

void test("decodePkcs7 reports when ContentInfo is missing a contentType OID", () => {
  const missingOid = seq(int(5), ctx0(octet(Uint8Array.of(0xaa))));
  const decoded = decodePkcs7(missingOid);
  assert.ok(decoded.warnings?.some(w => w.includes("contentType")));
  assert.strictEqual(decoded.contentType, undefined);
});

void test("decodePkcs7 surfaces non-SEQUENCE SignedData payloads", () => {
  const wrapper = seq(oid("1.2.840.113549.1.7.2"), ctx0(Uint8Array.of(0x01, 0x02)));
  const decoded = decodePkcs7(wrapper);
  assert.ok(decoded.warnings?.some(w => w.includes("SignedData is not a DER SEQUENCE")));
  assert.strictEqual(decoded.signerCount, undefined);
});

void test("decodePkcs7 surfaces missing SignedData version fields", () => {
  const badSignedData = seq(
    oid("1.2.840.113549.1.1.1"),
    set(),
    seq(oid("1.2.840.113549.1.7.1")),
    set()
  );
  const wrapper = seq(oid("1.2.840.113549.1.7.2"), ctx0(badSignedData));
  const decoded = decodePkcs7(wrapper);
  assert.ok(decoded.warnings?.some(w => w.includes("missing version")));
  assert.strictEqual(decoded.digestAlgorithms, undefined);
});

void test("decodePkcs7 counts certificates even without a SET wrapper", () => {
  const digestAlgorithm = seq(oid("1.3.14.3.2.26"), nul());
  const digestSet = set(digestAlgorithm);
  const payloadInfo = seq(oid("1.2.840.113549.1.7.1"));
  const simpleCert = seq(int(5));
  const rawCerts = ctx0(concat(simpleCert, simpleCert));
  const signerInfo = seq(
    int(1),
    seq(int(1), int(2)),
    seq(oid("1.3.14.3.2.26"), nul()),
    seq(oid("1.2.840.113549.1.1.1"), nul()),
    octet(Uint8Array.of(0x00))
  );
  const signerInfos = set(signerInfo);
  const signedData = seq(int(1), digestSet, payloadInfo, rawCerts, signerInfos);
  const wrapper = seq(oid("1.2.840.113549.1.7.2"), ctx0(signedData));
  const decoded = decodePkcs7(wrapper);
  assert.strictEqual(decoded.certificateCount, 2);
  assert.ok(!decoded.warnings?.length);
});

void test("decodePkcs7 treats malformed contentType OIDs as unknown", () => {
  const malformed = seq(tag(0x06, Uint8Array.of(0x81)));
  const decoded = decodePkcs7(malformed);
  assert.strictEqual(decoded.contentType, undefined);
  assert.ok(!decoded.warnings?.length);
});

void test("decodePkcs7 warns when SignedData is missing sections", () => {
  const signedData = seq(int(1));
  const wrapper = seq(oid("1.2.840.113549.1.7.2"), ctx0(signedData));
  const decoded = decodePkcs7(wrapper);
  assert.ok(decoded.warnings?.some(w => w.includes("digestAlgorithms")));
  assert.ok(decoded.warnings?.some(w => w.includes("encapContentInfo")));
  assert.ok(decoded.warnings?.some(w => w.includes("SignerInfos")));
});
