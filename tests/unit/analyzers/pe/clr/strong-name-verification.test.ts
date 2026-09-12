"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { verifyStrongNameSignature } from "../../../../../analyzers/pe/clr/strong-name-verification.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { makeStrongNamePeFixture } from "../../../../helpers/pe-strong-name-fixture.js";

// Assembly.HashAlgId values use ECMA-335 II.22.2 plus Windows ALG_ID values:
// https://carlwa.com/ecma-335/#ii.22.2-assembly-0x20
const SHA1_HASH_ALGORITHM_ID = 0x00008004;
const UNSUPPORTED_HASH_ALGORITHM_ID = SHA1_HASH_ALGORITHM_ID + Uint8Array.BYTES_PER_ELEMENT;
const STRONG_NAME_PUBLIC_KEY_ALGORITHM_ID = 0x00002400; // dnlib StrongNameKey RSA public-key blob.

const generatedBytes = (length: number): Uint8Array =>
  Uint8Array.from({ length }, (_, index) => index + Uint8Array.BYTES_PER_ELEMENT);

const writeUint32 = (view: DataView, offset: number, value: number): void =>
  view.setUint32(offset, value, true);

const makePublicKeyBlob = (): number[] => {
  const strongNameHeaderSize = Uint32Array.BYTES_PER_ELEMENT * 3;
  const cryptoApiBlobHeaderSize = Uint32Array.BYTES_PER_ELEMENT + Uint8Array.BYTES_PER_ELEMENT * 4;
  const rsaPublicKeyHeaderSize = Uint32Array.BYTES_PER_ELEMENT * 3;
  const publicExponentSize = Uint32Array.BYTES_PER_ELEMENT;
  const modulusSize = Uint32Array.BYTES_PER_ELEMENT * 2;
  const headerSize = strongNameHeaderSize + cryptoApiBlobHeaderSize + rsaPublicKeyHeaderSize;
  const bytes = new Uint8Array(headerSize + modulusSize);
  const view = new DataView(bytes.buffer);
  writeUint32(view, 0, STRONG_NAME_PUBLIC_KEY_ALGORITHM_ID);
  writeUint32(view, Uint32Array.BYTES_PER_ELEMENT, SHA1_HASH_ALGORITHM_ID);
  writeUint32(view, Uint32Array.BYTES_PER_ELEMENT * 2, cryptoApiBlobHeaderSize + rsaPublicKeyHeaderSize + modulusSize);
  view.setUint8(strongNameHeaderSize, 6); // CryptoAPI PUBLICKEYBLOB bType.
  view.setUint8(strongNameHeaderSize + Uint8Array.BYTES_PER_ELEMENT, 2); // CryptoAPI CUR_BLOB_VERSION.
  writeUint32(view, strongNameHeaderSize + Uint32Array.BYTES_PER_ELEMENT, STRONG_NAME_PUBLIC_KEY_ALGORITHM_ID);
  // Microsoft RSAPUBKEY.magic: RSA1 (0x31415352) for public keys.
  // https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey
  writeUint32(view, strongNameHeaderSize + cryptoApiBlobHeaderSize, 0x31415352);
  writeUint32(
    view,
    strongNameHeaderSize + cryptoApiBlobHeaderSize + Uint32Array.BYTES_PER_ELEMENT,
    modulusSize * 8
  );
  bytes.set(
    generatedBytes(publicExponentSize),
    strongNameHeaderSize + cryptoApiBlobHeaderSize + Uint32Array.BYTES_PER_ELEMENT * 2
  );
  bytes.set(generatedBytes(modulusSize), headerSize);
  return Array.from(bytes);
};

void test("verifyStrongNameSignature reports absent public keys without reading PE data", async () => {
  const issues: string[] = [];
  const verified = await verifyStrongNameSignature(
    new MockFile(generatedBytes(Uint32Array.BYTES_PER_ELEMENT)),
    undefined,
    generatedBytes(Uint32Array.BYTES_PER_ELEMENT),
    [],
    SHA1_HASH_ALGORITHM_ID,
    issues
  );

  assert.strictEqual(verified, null);
  assert.ok(issues.some(issue => issue.includes("public key blob is absent")));
});

void test("verifyStrongNameSignature rejects malformed RSA public-key blobs", async () => {
  const issues: string[] = [];
  const verified = await verifyStrongNameSignature(
    new MockFile(generatedBytes(Uint32Array.BYTES_PER_ELEMENT)),
    Array.from(generatedBytes(Uint32Array.BYTES_PER_ELEMENT)),
    generatedBytes(Uint32Array.BYTES_PER_ELEMENT),
    [],
    SHA1_HASH_ALGORITHM_ID,
    issues
  );

  assert.strictEqual(verified, null);
  assert.ok(issues.some(issue => issue.includes("too short")));
});

void test("verifyStrongNameSignature accepts ECMA Standard Public Key without an RSA warning", async () => {
  const issues: string[] = [];
  const verified = await verifyStrongNameSignature(
    new MockFile(generatedBytes(Uint32Array.BYTES_PER_ELEMENT)),
    // ECMA-335 II.6.2.1.3 Standard Public Key for Standard Library assemblies.
    [0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0],
    generatedBytes(Uint32Array.BYTES_PER_ELEMENT),
    [],
    SHA1_HASH_ALGORITHM_ID,
    issues
  );

  assert.strictEqual(verified, null);
  assert.deepStrictEqual(issues, []);
});

void test("verifyStrongNameSignature rejects unsupported hash algorithms before PE hashing", async () => {
  const issues: string[] = [];
  const verified = await verifyStrongNameSignature(
    new MockFile(generatedBytes(Uint32Array.BYTES_PER_ELEMENT)),
    makePublicKeyBlob(),
    generatedBytes(Uint32Array.BYTES_PER_ELEMENT),
    [],
    UNSUPPORTED_HASH_ALGORITHM_ID,
    issues
  );

  assert.strictEqual(verified, null);
  assert.ok(issues.some(issue => issue.includes("hash algorithm is unsupported")));
});

// Strong-name PUBLICKEYBLOB fields: SigAlgID +0, bType +12, bVersion +13,
// aiKeyAlg +16, RSA1 magic +20, bitlen +24, exponent +28, modulus +32.
// https://github.com/0xd4d/dnlib/blob/master/src/DotNet/StrongNameKey.cs
for (const [offset, value, warning] of [
  [0, 0, "not an RSA strong-name"],
  [12, 0, "not an RSA strong-name"],
  [13, 0, "unsupported RSA header"],
  [16, 0, "unsupported RSA header"],
  [20, 0, "not an RSA1"],
  [24, 0, "invalid RSA modulus size"],
  [24, 1, "invalid RSA modulus size"],
  [24, 0xffffffff, "invalid RSA modulus size"]
] as const) {
  void test(`strong-name verification rejects malformed RSA field ${offset} = ${value}`, async () => {
    const key = Uint8Array.from(makePublicKeyBlob());
    const issues: string[] = [];
    new DataView(key.buffer).setUint32(offset, value, true);
    assert.equal(await verifyStrongNameSignature(new MockFile(key), Array.from(key),
      new Uint8Array(1), [], SHA1_HASH_ALGORITHM_ID, issues), null);
    assert.match(issues.join(" "), new RegExp(warning));
  });
}

for (const [start, end] of [
  [-1, 3], [0.5, 4.5], [NaN, 4], [0, Infinity], [0, 3], [0, 0], [4, 0],
  [Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 4]
]) {
  void test(`strong-name verification rejects invalid signature range [${start}, ${end})`, async () => {
    const issues: string[] = [];
    assert.equal(await verifyStrongNameSignature(new MockFile(new Uint8Array(4)),
      makePublicKeyBlob(), new Uint8Array(4), [{ start: start!, end: end! }],
      SHA1_HASH_ALGORITHM_ID, issues), null);
    assert.deepEqual(issues, ["Strong-name signature file ranges are incomplete or outside the file."]);
  });
}

void test("strong-name verification rejects a fragment extending beyond EOF", async () => {
  const issues: string[] = [];
  assert.equal(await verifyStrongNameSignature(new MockFile(new Uint8Array(4)),
    makePublicKeyBlob(), new Uint8Array(4), [{ start: 1, end: 5 }],
    SHA1_HASH_ALGORITHM_ID, issues), null);
  assert.deepEqual(issues, ["Strong-name signature file ranges are incomplete or outside the file."]);
});

void test("strong-name verification reports unavailable WebCrypto", async context => {
  const issues: string[] = [];
  context.mock.getter(globalThis, "crypto", () => undefined);
  assert.equal(await verifyStrongNameSignature(new MockFile(new Uint8Array(4)),
    makePublicKeyBlob(), new Uint8Array(4), [], SHA1_HASH_ALGORITHM_ID, issues), null);
  assert.deepEqual(issues, ["WebCrypto is unavailable, so strong-name verification cannot run."]);
});

void test("strong-name verification reports an RSA operation rejection", async context => {
  const fixture = makeStrongNamePeFixture();
  const issues: string[] = [];
  context.mock.method(globalThis.crypto.subtle, "importKey", async () => ({}));
  context.mock.method(globalThis.crypto.subtle, "verify", async () => {
    throw new Error("RSA operation rejected");
  });
  assert.equal(await verifyStrongNameSignature(new MockFile(fixture.bytes), makePublicKeyBlob(),
    new Uint8Array(fixture.layout.signatureSize), [{
      start: fixture.layout.signatureOffset, end: fixture.layout.signatureEnd
    }], SHA1_HASH_ALGORITHM_ID, issues), null);
  assert.match(issues.join(" "), /RSA.*strong-name verification/);
});

// CryptoAPI ALG_ID values used by Assembly.HashAlgId; zero falls back to the public-key header.
// https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id
for (const [algorithm, expectedHash] of [
  [0, "SHA-1"], [0x800c, "SHA-256"], [0x800d, "SHA-384"], [0x800e, "SHA-512"]
] as const) {
  void test(`strong-name verification imports the RSA key with ${expectedHash}`, async context => {
    const fixture = makeStrongNamePeFixture();
    const issues: string[] = [];
    const imported = context.mock.method(globalThis.crypto.subtle, "importKey", async () => ({}));
    context.mock.method(globalThis.crypto.subtle, "verify", async () => false);
    assert.equal(await verifyStrongNameSignature(new MockFile(fixture.bytes), makePublicKeyBlob(),
      new Uint8Array(fixture.layout.signatureSize), [{
        start: fixture.layout.signatureOffset, end: fixture.layout.signatureEnd
      }], algorithm, issues), false);
    assert.deepEqual(imported.mock.calls[0]!.arguments[2], {
      name: "RSASSA-PKCS1-v1_5", hash: expectedHash
    });
    assert.deepEqual(issues, []);
  });
}
