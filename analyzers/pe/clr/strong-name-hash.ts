"use strict";

import { normalizeFileRanges, type FileRange } from "../layout/file-ranges.js";
import type { FileRangeReader } from "../../file-range-reader.js";

type PeStrongNameHashLayout = {
  ntHeadersOffset: number;
  optionalHeaderOffset: number;
  fixedOptionalHeaderSize: number;
  sectionHeadersOffset: number;
  sectionCount: number;
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

const readStrongNameHashLayout = async (
  reader: FileRangeReader,
  issues: string[]
): Promise<PeStrongNameHashLayout | null> => {
  // IMAGE_DOS_HEADER.e_lfanew is at 0x3c; PE signature + IMAGE_FILE_HEADER occupy 24 bytes.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
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

const pushRange = (ranges: FileRange[], start: number, end: number): void => {
  if (end > start) ranges.push({ start, end });
};

const appendSectionHashRanges = (
  ranges: FileRange[], start: number, end: number, signatureRanges: FileRange[]
): void => {
  let cursor = start;
  for (const signature of signatureRanges) {
    if (signature.end <= cursor) continue;
    if (signature.start >= end) break;
    pushRange(ranges, cursor, Math.min(end, signature.start));
    cursor = Math.max(cursor, signature.end);
  }
  pushRange(ranges, cursor, end);
};

const sectionHashRanges = (
  sectionBytes: Uint8Array,
  sectionCount: number,
  signatureRanges: FileRange[],
  fileSize: number
): FileRange[] => {
  const ranges: FileRange[] = [];
  const view = new DataView(sectionBytes.buffer, sectionBytes.byteOffset, sectionBytes.byteLength);
  // Hash sections in header order; normalize only the excluded physical fragments.
  // https://source.dot.net/Microsoft.DotNet.StrongName/Utils.cs.html (ComputeSigningHash)
  const excluded = normalizeFileRanges(signatureRanges);
  for (let index = 0; index < sectionCount; index += 1) {
    const sectionOffset = index * 0x28;
    const pointerToRawData = view.getUint32(sectionOffset + 0x14, true);
    appendSectionHashRanges(ranges, Math.min(pointerToRawData, fileSize),
      Math.min(pointerToRawData + view.getUint32(sectionOffset + 0x10, true), fileSize), excluded);
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
  ranges: FileRange[],
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

export const buildStrongNameHashInput = async (
  reader: FileRangeReader,
  signatureRanges: FileRange[],
  issues: string[]
): Promise<Uint8Array | null> => {
  const layout = await readStrongNameHashLayout(reader, issues);
  if (!layout) return null;
  const header = await buildStrongNameHeaderInput(reader, layout, issues);
  if (!header) return null;
  const totalLength = await appendRawSectionData(reader, header.chunks,
    sectionHashRanges(header.sectionBytes, layout.sectionCount, signatureRanges, reader.size),
    issues, header.totalLength);
  if (totalLength == null) return null;
  const input = new Uint8Array(totalLength);
  let offset = 0;
  header.chunks.forEach(chunk => {
    input.set(chunk, offset);
    offset += chunk.length;
  });
  return input;
};
