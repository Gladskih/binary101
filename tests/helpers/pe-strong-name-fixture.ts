"use strict";

import {
  COFF_FILE_HEADER_BYTE_LENGTH,
  COFF_FILE_HEADER_FIELDS,
  COFF_SECTION_HEADER_BYTE_LENGTH
} from "../../analyzers/coff/layout.js";
import type { PeClrHeader, PeClrMeta } from "../../analyzers/pe/clr/types.js";

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
const STRONG_NAME_PUBLIC_KEY_ALGORITHM_ID = 0x00002400; // dnlib StrongNameKey RSA public-key blob.
const WEBCRYPTO_STRONG_NAME_ALGORITHM = "RSASSA-PKCS1-v1_5";
const PE_SIGNATURE_BYTE_LENGTH = Uint32Array.BYTES_PER_ELEMENT;

export const makeClr = (rva: number, size: number, publicKey: number[] = []): PeClrHeader => ({
  cb: 0x48, // ECMA-335 II.25.3.3 CLR header size.
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
  return Uint8Array.from(atob(base64.padEnd(
    base64.length + (4 - base64.length % 4) % 4, "="
  )), char => char.charCodeAt(0));
};

export const expectedPublicKeyToken = async (publicKey: Uint8Array): Promise<string> => {
  // ECMA strong-name token: low 8 bytes of SHA-1(public key), displayed in reverse order.
  return Array.from(new Uint8Array(await globalThis.crypto.subtle.digest(
    "SHA-1", toArrayBuffer(publicKey)
  )).slice(-8)).reverse().map(byte => byte.toString(16).padStart(2, "0")).join("");
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

export const makePublicKeyBlob = async (key: CryptoKey): Promise<number[]> => {
  const jwk = await globalThis.crypto.subtle.exportKey("jwk", key);
  const modulus = base64UrlToBytes(jwk.n ?? "");
  const strongNameHeaderSize = Uint32Array.BYTES_PER_ELEMENT * 3;
  // 12-byte strong-name header, 8-byte PUBLICKEYSTRUC, 12-byte RSAPUBKEY.
  // https://github.com/0xd4d/dnlib/blob/master/src/DotNet/StrongNameKey.cs
  const publicKeyBlobHeaderSize = strongNameHeaderSize + 8 + 12;
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
  blob.set(reverse(base64UrlToBytes(jwk.e ?? "")).subarray(0, Uint32Array.BYTES_PER_ELEMENT), cursor.offset);
  blob.set(reverse(modulus), publicKeyBlobHeaderSize);
  return Array.from(blob);
};

export const makeStrongNamePeFixture = (): StrongNamePeFixture => {
  // PE32 field offsets and header sizes:
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
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

export const strongNameInputForFixture = (fixture: StrongNamePeFixture): Uint8Array => {
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

export const makeStrongNameKeyPair = () => {
  return globalThis.crypto.subtle.generateKey(
    {
      name: WEBCRYPTO_STRONG_NAME_ALGORITHM,
      modulusLength: 1024, // Small RSA key to keep cryptographic regression tests fast.
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-1"
    },
    true,
    ["sign", "verify"]
  );
};

export const signStrongNameInput = async (key: CryptoKey, input: Uint8Array): Promise<Uint8Array> =>
  reverse(new Uint8Array(await globalThis.crypto.subtle.sign(
    WEBCRYPTO_STRONG_NAME_ALGORITHM, key, toArrayBuffer(input)
  )));

export const makeValidSignedFixture = async (): Promise<StrongNameFixture> => {
  const keyPair = await makeStrongNameKeyPair();
  const pe = makeStrongNamePeFixture();
  pe.bytes.set(await signStrongNameInput(keyPair.privateKey, strongNameInputForFixture(pe)),
    pe.layout.signatureOffset);
  return {
    bytes: pe.bytes,
    clr: makeClr(pe.layout.signatureOffset, pe.layout.signatureSize, await makePublicKeyBlob(keyPair.publicKey))
  };
};

export const makeInvalidSignedFixture = async (): Promise<StrongNameFixture> => {
  const fixture = await makeValidSignedFixture();
  const tamperedOffset = makeStrongNamePeFixture().layout.sectionRawPointer + Uint32Array.BYTES_PER_ELEMENT;
  fixture.bytes[tamperedOffset] = (fixture.bytes[tamperedOffset] ?? 0) ^ (Uint8Array.BYTES_PER_ELEMENT << 8) - 1;
  return fixture;
};
