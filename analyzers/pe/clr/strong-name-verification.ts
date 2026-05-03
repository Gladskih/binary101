"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";

type FileByteRange = { start: number; end: number };
type PeStrongNameHashLayout = {
  ntHeadersOffset: number;
  optionalHeaderOffset: number;
  fixedOptionalHeaderSize: number;
  sectionHeadersOffset: number;
  sectionCount: number;
};
type RsaPublicKey = {
  hashAlgorithm: number;
  modulus: Uint8Array;
  exponent: Uint8Array;
};

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
const base64Url = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
const reverseBytes = (bytes: Uint8Array): Uint8Array => Uint8Array.from(bytes).reverse();
const trimLeadingZeroes = (bytes: Uint8Array): Uint8Array => {
  const first = bytes.findIndex(byte => byte !== 0);
  return first === -1 ? new Uint8Array([0]) : bytes.subarray(first);
};

const algorithmName = (hashAlgorithm: number): string | null => {
  // Assembly.HashAlgId values use ECMA-335 II.22.2 Assembly metadata plus Windows ALG_ID values:
  // https://carlwa.com/ecma-335/#ii.22.2-assembly-0x20
  if (hashAlgorithm === 0x00008004 || hashAlgorithm === 0) return "SHA-1";
  if (hashAlgorithm === 0x0000800c) return "SHA-256";
  if (hashAlgorithm === 0x0000800d) return "SHA-384";
  if (hashAlgorithm === 0x0000800e) return "SHA-512";
  return null;
};

const readExactBytes = async (
  reader: FileRangeReader,
  offset: number,
  size: number,
  issues: string[],
  context: string
): Promise<Uint8Array | null> => {
  const bytes = await reader.readBytes(offset, size);
  if (bytes.length === size) return bytes;
  issues.push(`${context} is truncated.`);
  return null;
};

const parseRsaPublicKey = (publicKey: number[] | undefined, issues: string[]): RsaPublicKey | null => {
  if (!publicKey?.length) {
    issues.push("Assembly public key blob is absent.");
    return null;
  }
  const bytes = new Uint8Array(publicKey);
  if (bytes.length < 32) {
    issues.push("Assembly public key blob is too short for an RSA public key.");
    return null;
  }
  return parseRsaPublicKeyFields(bytes, new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength), issues);
};

const parseRsaPublicKeyFields = (
  bytes: Uint8Array,
  view: DataView,
  issues: string[]
): RsaPublicKey | null => {
  // PublicKey blob layout follows the CLR strong-name PUBLICKEYBLOB/CryptoAPI RSA1 shape:
  // https://github.com/0xd4d/dnlib/blob/master/src/DotNet/StrongNameKey.cs
  if (view.getUint32(0, true) !== 0x00002400 || view.getUint8(12) !== 6) {
    issues.push("Assembly public key blob is not an RSA strong-name public key.");
    return null;
  }
  if (view.getUint8(13) !== 2 || view.getUint32(16, true) !== 0x00002400) {
    issues.push("Assembly public key blob has an unsupported RSA header.");
    return null;
  }
  if (view.getUint32(20, true) !== 0x31415352) {
    issues.push("Assembly public key blob is not an RSA1 public key.");
    return null;
  }
  const modulusBytes = view.getUint32(24, true) / 8;
  if (!Number.isInteger(modulusBytes) || modulusBytes <= 0 || 32 + modulusBytes > bytes.length) {
    issues.push("Assembly public key blob has an invalid RSA modulus size.");
    return null;
  }
  return {
    hashAlgorithm: view.getUint32(4, true),
    modulus: reverseBytes(bytes.subarray(32, 32 + modulusBytes)),
    exponent: trimLeadingZeroes(reverseBytes(bytes.subarray(28, 32)))
  };
};

const readStrongNameHashLayout = async (
  reader: FileRangeReader,
  issues: string[]
): Promise<PeStrongNameHashLayout | null> => {
  const dos = await readExactBytes(reader, 0, 0x40, issues, "DOS header");
  if (!dos) return null;
  const ntHeadersOffset = new DataView(dos.buffer, dos.byteOffset, dos.byteLength).getUint32(0x3c, true);
  if (ntHeadersOffset + 24 > reader.size) {
    issues.push("PE header offset is outside the file.");
    return null;
  }
  const nt = await readExactBytes(reader, ntHeadersOffset, 24, issues, "PE header");
  if (!nt) return null;
  return readStrongNameHashLayoutFromNt(reader, ntHeadersOffset, nt, issues);
};

const readStrongNameHashLayoutFromNt = async (
  reader: FileRangeReader,
  ntHeadersOffset: number,
  nt: Uint8Array,
  issues: string[]
): Promise<PeStrongNameHashLayout | null> => {
  const ntView = new DataView(nt.buffer, nt.byteOffset, nt.byteLength);
  if (ntView.getUint32(0, true) !== 0x00004550) {
    issues.push("PE signature is missing while verifying the strong name.");
    return null;
  }
  const optionalHeaderOffset = ntHeadersOffset + 24;
  const magic = await readExactBytes(reader, optionalHeaderOffset, 2, issues, "PE optional header");
  if (!magic) return null;
  const optionalMagic = new DataView(magic.buffer, magic.byteOffset, magic.byteLength).getUint16(0, true);
  const fixedOptionalHeaderSize = optionalMagic === 0x010b ? 0x60 : optionalMagic === 0x020b ? 0x70 : 0;
  if (!fixedOptionalHeaderSize) {
    issues.push("PE optional header magic is unsupported for strong-name verification.");
    return null;
  }
  return {
    ntHeadersOffset,
    optionalHeaderOffset,
    fixedOptionalHeaderSize,
    sectionHeadersOffset: optionalHeaderOffset + fixedOptionalHeaderSize + 16 * 8,
    sectionCount: ntView.getUint16(6, true)
  };
};

const readZeroedHeaderPart = async (
  reader: FileRangeReader,
  offset: number,
  size: number,
  zeroOffset: number,
  zeroSize: number,
  issues: string[],
  context: string
): Promise<Uint8Array | null> => {
  const bytes = await readExactBytes(reader, offset, size, issues, context);
  if (!bytes) return null;
  const copy = Uint8Array.from(bytes);
  copy.fill(0, zeroOffset, zeroOffset + zeroSize);
  return copy;
};

const pushRange = (ranges: FileByteRange[], start: number, end: number): void => {
  if (end > start) ranges.push({ start, end });
};

const sectionHashRanges = (
  sectionBytes: Uint8Array,
  sectionCount: number,
  signatureOffset: number,
  signatureSize: number,
  fileSize: number
): FileByteRange[] => {
  const ranges: FileByteRange[] = [];
  const view = new DataView(sectionBytes.buffer, sectionBytes.byteOffset, sectionBytes.byteLength);
  const signatureEnd = signatureOffset + signatureSize;
  for (let index = 0; index < sectionCount; index += 1) {
    const sectionOffset = index * 0x28;
    const sizeOfRawData = view.getUint32(sectionOffset + 0x10, true);
    const pointerToRawData = view.getUint32(sectionOffset + 0x14, true);
    const start = Math.min(pointerToRawData, fileSize);
    const end = Math.min(pointerToRawData + sizeOfRawData, fileSize);
    pushRange(ranges, start, Math.min(end, signatureOffset));
    pushRange(ranges, Math.max(start, signatureEnd), end);
  }
  return ranges;
};

const appendBytes = (
  chunks: Uint8Array[],
  totalLength: number,
  bytes: Uint8Array
): number => {
  chunks.push(bytes);
  return totalLength + bytes.length;
};

const appendRawSectionData = async (
  reader: FileRangeReader,
  chunks: Uint8Array[],
  ranges: FileByteRange[],
  issues: string[],
  totalLength: number
): Promise<number | null> => {
  let nextLength = totalLength;
  for (const range of ranges) {
    const bytes = await readExactBytes(reader, range.start, range.end - range.start, issues, "PE section data");
    if (!bytes) return null;
    nextLength = appendBytes(chunks, nextLength, bytes);
  }
  return nextLength;
};

const buildStrongNameHeaderInput = async (
  reader: FileRangeReader,
  layout: PeStrongNameHashLayout,
  issues: string[]
): Promise<{ chunks: Uint8Array[]; totalLength: number; sectionBytes: Uint8Array } | null> => {
  const dos = await readExactBytes(reader, 0, layout.ntHeadersOffset, issues, "DOS header");
  const nt = await readExactBytes(reader, layout.ntHeadersOffset, 0x18, issues, "PE header");
  const optional = await readZeroedHeaderPart(reader, layout.optionalHeaderOffset, layout.fixedOptionalHeaderSize, 0x40, 4, issues, "PE optional header");
  const directories = await readZeroedHeaderPart(reader, layout.optionalHeaderOffset + layout.fixedOptionalHeaderSize, 16 * 8, 4 * 8, 8, issues, "PE data directories");
  const sectionBytes = await readExactBytes(reader, layout.sectionHeadersOffset, layout.sectionCount * 0x28, issues, "PE section headers");
  if (!dos || !nt || !optional || !directories || !sectionBytes) return null;
  const chunks: Uint8Array[] = [];
  let totalLength = appendBytes(chunks, 0, dos);
  totalLength = appendBytes(chunks, totalLength, nt);
  totalLength = appendBytes(chunks, totalLength, optional);
  totalLength = appendBytes(chunks, totalLength, directories);
  totalLength = appendBytes(chunks, totalLength, sectionBytes);
  return { chunks, totalLength, sectionBytes };
};

const buildStrongNameHashInput = async (
  reader: FileRangeReader,
  signatureOffset: number,
  signatureSize: number,
  issues: string[]
): Promise<Uint8Array | null> => {
  const layout = await readStrongNameHashLayout(reader, issues);
  if (!layout) return null;
  const header = await buildStrongNameHeaderInput(reader, layout, issues);
  if (!header) return null;
  const ranges = sectionHashRanges(
    header.sectionBytes,
    layout.sectionCount,
    signatureOffset,
    signatureSize,
    reader.size
  );
  const totalLength = await appendRawSectionData(reader, header.chunks, ranges, issues, header.totalLength);
  if (totalLength == null) return null;
  const input = new Uint8Array(totalLength);
  let offset = 0;
  header.chunks.forEach(chunk => {
    input.set(chunk, offset);
    offset += chunk.length;
  });
  return input;
};

export const verifyStrongNameSignature = async (
  reader: FileRangeReader,
  publicKey: number[] | undefined,
  signature: Uint8Array,
  signatureOffset: number,
  hashAlgorithm: number,
  issues: string[]
): Promise<boolean | null> => {
  const rsaPublicKey = parseRsaPublicKey(publicKey, issues);
  if (!rsaPublicKey) return null;
  const hashName = algorithmName(hashAlgorithm || rsaPublicKey.hashAlgorithm);
  if (!hashName) {
    issues.push("Assembly hash algorithm is unsupported for strong-name verification.");
    return null;
  }
  if (!globalThis.crypto?.subtle) {
    issues.push("WebCrypto is unavailable, so strong-name verification cannot run.");
    return null;
  }
  const input = await buildStrongNameHashInput(reader, signatureOffset, signature.length, issues);
  if (!input) return null;
  try {
    const key = await globalThis.crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: base64Url(trimLeadingZeroes(rsaPublicKey.modulus)), e: base64Url(trimLeadingZeroes(rsaPublicKey.exponent)), ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: hashName },
      false,
      ["verify"]
    );
    return globalThis.crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, toArrayBuffer(reverseBytes(signature)), toArrayBuffer(input));
  } catch {
    issues.push("RSA public key blob could not be imported for strong-name verification.");
    return null;
  }
};
