"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { verifyStrongNameSignature } from "../../analyzers/pe/clr/strong-name-verification.js";
import { MockFile } from "../helpers/mock-file.js";

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
    0,
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
    0,
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
    0,
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
    0,
    UNSUPPORTED_HASH_ALGORITHM_ID,
    issues
  );

  assert.strictEqual(verified, null);
  assert.ok(issues.some(issue => issue.includes("hash algorithm is unsupported")));
});
