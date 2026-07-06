"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  COFF_FILE_HEADER_BYTE_LENGTH,
  COFF_FILE_HEADER_FIELDS,
  COFF_SECTION_HEADER_BYTE_LENGTH
} from "../../../../../analyzers/coff/layout.js";
import { formatPublicKeyToken, parseStrongName } from "../../../../../analyzers/pe/clr/strong-name.js";
import type { PeClrHeader, PeClrMeta } from "../../../../../analyzers/pe/clr/types.js";
import { MockFile } from "../../../../helpers/mock-file.js";

type StrongNameFixture = { bytes: Uint8Array; clr: PeClrHeader };

type StrongNamePeLayout = {
  checksumRelativeOffset: number;
  dataDirectoriesOffset: number;
  dataDirectorySize: number;
  fileSize: number;
  ntHeadersOffset: number;
  optionalHeaderOffset: number;
  sectionHeaderOffset: number;
  sectionRawPointer: number;
  securityDirectoryIndex: number;
  signatureOffset: number;
  signatureSize: number;
  signatureEnd: number;
};

type StrongNamePeFixture = { bytes: Uint8Array; layout: StrongNamePeLayout };

const SHA1_HASH_ALGORITHM_ID = 0x00008004; // ECMA-335 Assembly.HashAlgId SHA-1 / CALG_SHA1.
const CLR_HEADER_SIZE = 0x48; // ECMA-335 II.25.3.3 current CLR header size.
const TEST_RSA_KEY_BITS = 1024; // Smallest WebCrypto RSA size accepted by Node for fast tests.
const STRONG_NAME_PUBLIC_KEY_ALGORITHM_ID = 0x00002400; // dnlib StrongNameKey RSA public-key blob.
const WEBCRYPTO_STRONG_NAME_ALGORITHM = "RSASSA-PKCS1-v1_5";
const PE_SIGNATURE_BYTE_LENGTH = Uint32Array.BYTES_PER_ELEMENT;

const makeClr = (rva: number, size: number, publicKey: number[] = []): PeClrHeader => ({
  cb: CLR_HEADER_SIZE,
  MajorRuntimeVersion: 4,
  MinorRuntimeVersion: 0,
  MetaDataRVA: 0,
  MetaDataSize: 0,
  Flags: 0,
  EntryPointToken: 0,
  ResourcesRVA: 0,
  ResourcesSize: 0,
  StrongNameSignatureRVA: rva,
  StrongNameSignatureSize: size,
  CodeManagerTableRVA: 0,
  CodeManagerTableSize: 0,
  VTableFixupsRVA: 0,
  VTableFixupsSize: 0,
  ExportAddressTableJumpsRVA: 0,
  ExportAddressTableJumpsSize: 0,
  ManagedNativeHeaderRVA: 0,
  ManagedNativeHeaderSize: 0,
  meta: makeStrongNameMetadata(publicKey)
});

const reverse = (bytes: Uint8Array): Uint8Array => Uint8Array.from(bytes).reverse();

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

const makeStrongNameMetadata = (publicKey: number[]): PeClrMeta => ({
  streams: [],
  tables: {
    assembly: { hashAlgorithm: SHA1_HASH_ALGORITHM_ID, publicKey }
  } as NonNullable<PeClrMeta["tables"]>
});

const base64UrlToBytes = (value: string): Uint8Array => {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, "=");
  return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
};

const expectedPublicKeyToken = async (publicKey: Uint8Array): Promise<string> => {
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-1", toArrayBuffer(publicKey)));
  // ECMA strong-name token: low 8 bytes of SHA-1(public key), displayed in reverse order.
  const tokenBytes = Array.from(digest.slice(-8)).reverse();
  return tokenBytes.map(byte => byte.toString(16).padStart(2, "0")).join("");
};

const uint32 = (target: Uint8Array, offset: number, value: number): void =>
  new DataView(target.buffer).setUint32(offset, value, true);

const uint16 = (target: Uint8Array, offset: number, value: number): void =>
  new DataView(target.buffer).setUint16(offset, value, true);

const writeUint8 = (view: DataView, cursor: { offset: number }, value: number): void => {
  view.setUint8(cursor.offset, value);
  cursor.offset += Uint8Array.BYTES_PER_ELEMENT;
};

const writeUint32 = (view: DataView, cursor: { offset: number }, value: number): void => {
  view.setUint32(cursor.offset, value, true);
  cursor.offset += Uint32Array.BYTES_PER_ELEMENT;
};

const makePublicKeyBlob = async (key: CryptoKey): Promise<number[]> => {
  const jwk = await globalThis.crypto.subtle.exportKey("jwk", key);
  const modulus = base64UrlToBytes(jwk.n ?? "");
  const exponent = base64UrlToBytes(jwk.e ?? "");
  const strongNameHeaderSize = Uint32Array.BYTES_PER_ELEMENT * 3;
  const cryptoApiBlobHeaderSize = Uint32Array.BYTES_PER_ELEMENT + Uint8Array.BYTES_PER_ELEMENT * 4;
  const rsaPublicKeyHeaderSize = Uint32Array.BYTES_PER_ELEMENT * 3;
  const publicExponentSize = Uint32Array.BYTES_PER_ELEMENT;
  const publicKeyBlobHeaderSize = strongNameHeaderSize + cryptoApiBlobHeaderSize + rsaPublicKeyHeaderSize;
  const blob = new Uint8Array(publicKeyBlobHeaderSize + modulus.length);
  const view = new DataView(blob.buffer);
  const cursor = { offset: 0 };
  writeUint32(view, cursor, STRONG_NAME_PUBLIC_KEY_ALGORITHM_ID);
  writeUint32(view, cursor, SHA1_HASH_ALGORITHM_ID);
  writeUint32(view, cursor, publicKeyBlobHeaderSize - strongNameHeaderSize + modulus.length);
  writeUint8(view, cursor, 6); // CryptoAPI PUBLICKEYBLOB bType.
  writeUint8(view, cursor, 2); // CryptoAPI CUR_BLOB_VERSION.
  writeUint8(view, cursor, 0);
  writeUint8(view, cursor, 0);
  writeUint32(view, cursor, STRONG_NAME_PUBLIC_KEY_ALGORITHM_ID);
  // Microsoft RSAPUBKEY.magic: RSA1 (0x31415352) for public keys.
  // https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey
  writeUint32(view, cursor, 0x31415352);
  writeUint32(view, cursor, modulus.length * 8);
  blob.set(reverse(exponent).subarray(0, publicExponentSize), cursor.offset);
  blob.set(reverse(modulus), publicKeyBlobHeaderSize);
  return Array.from(blob);
};

const makeStrongNamePeFixture = (): StrongNamePeFixture => {
  const dosHeaderProbeSize = 0x40; // Verifier reads the DOS header through e_lfanew.
  const ntHeadersOffset = dosHeaderProbeSize * 2;
  const optionalHeaderOffset = ntHeadersOffset + PE_SIGNATURE_BYTE_LENGTH + COFF_FILE_HEADER_BYTE_LENGTH;
  const pe32FixedOptionalHeaderSize = 0x60; // PE/COFF PE32 optional header before directories.
  const dataDirectoryCount = 16; // PE/COFF NumberOfRvaAndSizes for the standard directory array.
  const dataDirectorySize = Uint32Array.BYTES_PER_ELEMENT * 2;
  const dataDirectoriesOffset = optionalHeaderOffset + pe32FixedOptionalHeaderSize;
  const sectionHeaderOffset = dataDirectoriesOffset + dataDirectoryCount * dataDirectorySize;
  const sectionRawPointer = ntHeadersOffset * 4;
  const sectionRawSize = sectionRawPointer / 2;
  const signatureSize = sectionRawSize / 2;
  const signatureOffset = sectionRawPointer + signatureSize / 2;
  const layout: StrongNamePeLayout = {
    checksumRelativeOffset: 0x40, // PE/COFF CheckSum field offset within PE32 optional header.
    dataDirectoriesOffset,
    dataDirectorySize,
    fileSize: sectionRawPointer + sectionRawSize,
    ntHeadersOffset,
    optionalHeaderOffset,
    sectionHeaderOffset,
    sectionRawPointer,
    securityDirectoryIndex: 4, // PE/COFF IMAGE_DIRECTORY_ENTRY_SECURITY.
    signatureOffset,
    signatureSize,
    signatureEnd: signatureOffset + signatureSize
  };
  const bytes = new Uint8Array(layout.fileSize);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x5a4d, true); // PE/COFF DOS signature "MZ".
  view.setUint32(dosHeaderProbeSize - Uint32Array.BYTES_PER_ELEMENT, ntHeadersOffset, true);
  view.setUint32(ntHeadersOffset, 0x00004550, true); // PE/COFF signature "PE\0\0".
  uint16(bytes, ntHeadersOffset + PE_SIGNATURE_BYTE_LENGTH + COFF_FILE_HEADER_FIELDS.NumberOfSections.offset, 1);
  uint16(
    bytes,
    ntHeadersOffset + PE_SIGNATURE_BYTE_LENGTH + COFF_FILE_HEADER_FIELDS.SizeOfOptionalHeader.offset,
    pe32FixedOptionalHeaderSize + dataDirectoryCount * dataDirectorySize
  );
  uint16(bytes, optionalHeaderOffset, 0x010b); // PE/COFF PE32 optional header magic.
  uint32(bytes, dataDirectoriesOffset - Uint32Array.BYTES_PER_ELEMENT, dataDirectoryCount);
  uint32(bytes, sectionHeaderOffset + Uint32Array.BYTES_PER_ELEMENT * 2, sectionRawSize);
  uint32(bytes, sectionHeaderOffset + Uint32Array.BYTES_PER_ELEMENT * 3, sectionRawPointer * dataDirectoryCount);
  uint32(bytes, sectionHeaderOffset + Uint32Array.BYTES_PER_ELEMENT * 4, sectionRawSize);
  uint32(bytes, sectionHeaderOffset + Uint32Array.BYTES_PER_ELEMENT * 5, sectionRawPointer);
  for (let offset = sectionRawPointer; offset < layout.fileSize; offset += 1) {
    bytes[offset] = offset % (Uint8Array.BYTES_PER_ELEMENT << 8);
  }
  bytes.fill(0, signatureOffset, layout.signatureEnd);
  return { bytes, layout };
};

const strongNameInputForFixture = (fixture: StrongNamePeFixture): Uint8Array => {
  const { bytes, layout } = fixture;
  const optional = Uint8Array.from(bytes.subarray(layout.optionalHeaderOffset, layout.dataDirectoriesOffset));
  const directories = Uint8Array.from(bytes.subarray(layout.dataDirectoriesOffset, layout.sectionHeaderOffset));
  optional.fill(0, layout.checksumRelativeOffset, layout.checksumRelativeOffset + Uint32Array.BYTES_PER_ELEMENT);
  directories.fill(
    0,
    layout.securityDirectoryIndex * layout.dataDirectorySize,
    (layout.securityDirectoryIndex + 1) * layout.dataDirectorySize
  );
  return new Uint8Array([
    ...bytes.subarray(0, layout.ntHeadersOffset),
    ...bytes.subarray(layout.ntHeadersOffset, layout.optionalHeaderOffset),
    ...optional,
    ...directories,
    ...bytes.subarray(layout.sectionHeaderOffset, layout.sectionHeaderOffset + COFF_SECTION_HEADER_BYTE_LENGTH),
    ...bytes.subarray(layout.sectionRawPointer, layout.signatureOffset),
    ...bytes.subarray(layout.signatureEnd, layout.fileSize)
  ]);
};

const makeValidSignedFixture = async (): Promise<StrongNameFixture> => {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    {
      name: WEBCRYPTO_STRONG_NAME_ALGORITHM,
      modulusLength: TEST_RSA_KEY_BITS,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-1"
    },
    true,
    ["sign", "verify"]
  );
  const pe = makeStrongNamePeFixture();
  const signature = new Uint8Array(await globalThis.crypto.subtle.sign(
    WEBCRYPTO_STRONG_NAME_ALGORITHM,
    keyPair.privateKey,
    toArrayBuffer(strongNameInputForFixture(pe))
  ));
  pe.bytes.set(reverse(signature), pe.layout.signatureOffset);
  return {
    bytes: pe.bytes,
    clr: makeClr(pe.layout.signatureOffset, pe.layout.signatureSize, await makePublicKeyBlob(keyPair.publicKey))
  };
};

const makeInvalidSignedFixture = async (): Promise<StrongNameFixture> => {
  const fixture = await makeValidSignedFixture();
  const tamperedOffset = makeStrongNamePeFixture().layout.sectionRawPointer + Uint32Array.BYTES_PER_ELEMENT;
  fixture.bytes[tamperedOffset] = (fixture.bytes[tamperedOffset] ?? 0) ^ (Uint8Array.BYTES_PER_ELEMENT << 8) - 1;
  return fixture;
};

void test("formatPublicKeyToken uses the ECMA strong-name token byte order", async () => {
  const publicKey = Uint8Array.from({ length: Uint32Array.BYTES_PER_ELEMENT }, (_, index) => index + 1);
  const token = await formatPublicKeyToken(Array.from(publicKey));

  assert.strictEqual(token, await expectedPublicKeyToken(publicKey));
});

void test("parseStrongName reports absent signatures", async () => {
  const pe = makeStrongNamePeFixture();
  const parsed = await parseStrongName(
    new MockFile(new Uint8Array(pe.layout.fileSize)),
    rva => rva,
    makeClr(0, 0)
  );

  assert.strictEqual(parsed.status, "absent");
  assert.strictEqual(parsed.verification, "unknown");
});

void test("parseStrongName detects delay-signed all-zero signatures", async () => {
  const pe = makeStrongNamePeFixture();
  const parsed = await parseStrongName(
    new MockFile(new Uint8Array(pe.layout.fileSize)),
    rva => rva,
    makeClr(pe.layout.signatureOffset, pe.layout.signatureSize)
  );

  assert.strictEqual(parsed.status, "delay-signed");
  assert.match(parsed.verificationNote, /delay-signed/);
});

void test("parseStrongName reports unmapped and truncated signatures", async () => {
  const pe = makeStrongNamePeFixture();
  const unmapped = await parseStrongName(
    new MockFile(new Uint8Array(pe.layout.fileSize)),
    () => null,
    makeClr(pe.layout.signatureOffset, pe.layout.signatureSize)
  );
  const truncated = await parseStrongName(
    new MockFile(new Uint8Array(pe.layout.signatureOffset + Uint8Array.BYTES_PER_ELEMENT)),
    rva => rva,
    makeClr(pe.layout.signatureOffset, pe.layout.signatureSize)
  );

  assert.strictEqual(unmapped.status, "unmapped");
  assert.strictEqual(truncated.status, "truncated");
  assert.ok(truncated.issues.some(issue => issue.includes("end of file")));
});

void test("parseStrongName verifies valid RSA strong-name signatures", async () => {
  const fixture = await makeValidSignedFixture();

  const parsed = await parseStrongName(new MockFile(fixture.bytes), rva => rva, fixture.clr);

  assert.strictEqual(parsed.status, "present");
  assert.strictEqual(parsed.verification, "valid");
  assert.match(parsed.verificationNote, /matches/);
});

void test("parseStrongName reports invalid RSA strong-name signatures", async () => {
  const fixture = await makeInvalidSignedFixture();

  const parsed = await parseStrongName(new MockFile(fixture.bytes), rva => rva, fixture.clr);

  assert.strictEqual(parsed.status, "present");
  assert.strictEqual(parsed.verification, "invalid");
  assert.match(parsed.verificationNote, /does not match/);
});
