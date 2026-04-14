"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { ContentInfo, SignedData } from "../../analyzers/pe/authenticode/pkijs-runtime.js";
import { verifyPkcs7Signatures } from "../../analyzers/pe/authenticode/pkijs.js";
import { createSignedAuthenticodeCmsFixture } from "../fixtures/pe-authenticode-signed-cms-fixtures.js";

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out.buffer;
};

const parseSignedData = (payload: Uint8Array): SignedData => {
  const contentInfo = ContentInfo.fromBER(toArrayBuffer(payload));
  return new SignedData({ schema: contentInfo.content });
};

const encodeSignedData = (signedData: SignedData): Uint8Array =>
  new Uint8Array(
    new ContentInfo({
      contentType: ContentInfo.SIGNED_DATA,
      content: signedData.toSchema(true)
    }).toSchema().toBER()
  );

const tamperSignerSignature = (payload: Uint8Array): Uint8Array => {
  const signedData = parseSignedData(payload);
  const signature = signedData.signerInfos[0]?.signature.valueBlock.valueHexView;
  if (!signature?.length) {
    throw new Error("Signed CMS fixture is missing the signer signature bytes.");
  }
  const firstByte = signature[0];
  if (firstByte === undefined) {
    throw new Error("Signed CMS fixture is missing the first signer signature byte.");
  }
  signature[0] = firstByte ^ 0xff;
  return encodeSignedData(signedData);
};

const removeSignerCertificates = (payload: Uint8Array): Uint8Array => {
  const signedData = parseSignedData(payload);
  signedData.certificates = [];
  return encodeSignedData(signedData);
};

void test("verifyPkcs7Signatures verifies a valid Authenticode CMS signer", async () => {
  const { payload } = await createSignedAuthenticodeCmsFixture();

  const verified = await verifyPkcs7Signatures(payload);

  assert.strictEqual(verified.signerVerifications?.length, 1);
  assert.strictEqual(verified.signerVerifications?.[0]?.signatureVerified, true);
  assert.strictEqual(verified.warnings, undefined);
});

void test("verifyPkcs7Signatures reports invalid signer signatures without hiding the signer result", async () => {
  const { payload } = await createSignedAuthenticodeCmsFixture();

  const verified = await verifyPkcs7Signatures(tamperSignerSignature(payload));

  assert.strictEqual(verified.signerVerifications?.[0]?.signatureVerified, false);
  assert.ok(verified.warnings?.some(warning => /signature/i.test(warning)));
});

void test("verifyPkcs7Signatures reports missing signer certificates as warnings", async () => {
  const { payload } = await createSignedAuthenticodeCmsFixture();

  const verified = await verifyPkcs7Signatures(removeSignerCertificates(payload));

  assert.strictEqual(verified.signerVerifications?.[0]?.code, 3);
  assert.ok(verified.warnings?.some(warning => /signer certificate/i.test(warning)));
});

void test("verifyPkcs7Signatures reports malformed BER payloads", async () => {
  const verified = await verifyPkcs7Signatures(Uint8Array.of(0x30, 0x10, 0x06, 0x01));

  assert.strictEqual(verified.signerVerifications, undefined);
  assert.ok(verified.warnings?.some(warning => /BER|decode|ContentInfo/i.test(warning)));
});
