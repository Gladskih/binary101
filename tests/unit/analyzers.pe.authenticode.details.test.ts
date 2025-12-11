"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodePkcs7 } from "../../analyzers/pe/authenticode.js";

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

const printableString = (value: string): Uint8Array =>
  tag(0x13, Uint8Array.from(value, ch => ch.charCodeAt(0)));

const utcTime = (value: string): Uint8Array =>
  tag(0x17, Uint8Array.from(value, ch => ch.charCodeAt(0)));

const rdn = (oidValue: string, value: string): Uint8Array =>
  set(seq(oid(oidValue), printableString(value)));

const name = (...rdns: Uint8Array[]): Uint8Array => seq(...rdns);

const buildCertificate = (): Uint8Array => {
  const issuer = name(rdn("2.5.4.3", "Test Issuer"));
  const subject = name(rdn("2.5.4.3", "Test Subject"));
  const validity = seq(utcTime("240101000000Z"), utcTime("250101000000Z"));
  const tbs = seq(ctx0(int(2)), int(0x1234), seq(oid("1.2.3.4")), issuer, validity, subject);
  return seq(tbs, seq(oid("1.2.3.4")), tag(0x03, Uint8Array.of(0x00)));
};

const buildSpcIndirectDataWithDigest = (): Uint8Array => {
  const algId = seq(oid("2.16.840.1.101.3.4.2.1"), nul());
  const digestInfo = seq(algId, octet(Uint8Array.of(0xde, 0xad, 0xbe, 0xef)));
  const data = seq(oid("1.2.3.4"));
  return seq(data, digestInfo);
};

const buildSignedDataDetailed = (): Uint8Array => {
  const digestAlgorithm = seq(oid("2.16.840.1.101.3.4.2.1"), nul());
  const spc = buildSpcIndirectDataWithDigest();
  const signedContent = seq(oid("1.3.6.1.4.1.311.2.1.4"), ctx0(octet(spc)));
  const certificates = ctx0(set(buildCertificate()));
  const signerInfo = seq(
    int(1),
    seq(name(rdn("2.5.4.3", "Test Issuer")), int(0x1234)),
    seq(oid("2.16.840.1.101.3.4.2.1"), nul()),
    tag(0xa0, seq(oid("1.2.840.113549.1.9.5"), set(utcTime("240101000000Z")))),
    seq(oid("1.2.840.113549.1.1.1"), nul()),
    octet(Uint8Array.of(0x00))
  );
  const signerInfos = set(signerInfo);
  return seq(int(1), set(digestAlgorithm), signedContent, certificates, signerInfos);
};

void test("decodePkcs7 extracts signer, certificate, and file digest details", () => {
  const signedData = buildSignedDataDetailed();
  const wrapper = seq(oid("1.2.840.113549.1.7.2"), ctx0(signedData));
  const decoded = decodePkcs7(wrapper);
  assert.strictEqual(decoded.fileDigestAlgorithmName, "sha256");
  assert.strictEqual(decoded.fileDigest, "deadbeef");
  assert.strictEqual(decoded.signers?.length, 1);
  assert.ok(decoded.signers?.[0]?.issuer?.includes("CN=Test Issuer"));
  assert.strictEqual(decoded.signers?.[0]?.digestAlgorithmName, "sha256");
  assert.ok(decoded.signers?.[0]?.signingTime);
  assert.strictEqual(decoded.certificates?.length, 1);
  assert.ok(decoded.certificates?.[0]?.subject?.includes("CN=Test Subject"));
  assert.ok(decoded.certificates?.[0]?.issuer?.includes("CN=Test Issuer"));
  assert.ok(decoded.certificates?.[0]?.notBefore?.includes("2024-01-01"));
});

