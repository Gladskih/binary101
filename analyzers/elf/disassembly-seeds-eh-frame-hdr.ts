"use strict";

import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";
import type { ElfDisassemblySeedGroup } from "./disassembly-seeds-types.js";

const PT_GNU_EH_FRAME = 0x6474e550;

const DW_EH_PE_omit = 0xff;
const DW_EH_PE_ptr = 0x00;
const DW_EH_PE_uleb128 = 0x01;
const DW_EH_PE_udata2 = 0x02;
const DW_EH_PE_udata4 = 0x03;
const DW_EH_PE_udata8 = 0x04;
const DW_EH_PE_sleb128 = 0x09;
const DW_EH_PE_sdata2 = 0x0a;
const DW_EH_PE_sdata4 = 0x0b;
const DW_EH_PE_sdata8 = 0x0c;

const DW_EH_PE_pcrel = 0x10;
const DW_EH_PE_datarel = 0x30;
const DW_EH_PE_indirect = 0x80;

const toSafeIndex = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

const readUleb128 = (bytes: Uint8Array<ArrayBuffer>, start: number): { value: bigint; size: number } | null => {
  let result = 0n;
  let shift = 0n;
  for (let index = 0; index < 10; index += 1) {
    const pos = start + index;
    if (pos >= bytes.byteLength) return null;
    const byte = bytes[pos] ?? 0;
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return { value: result, size: index + 1 };
    shift += 7n;
  }
  return null;
};

const readSleb128 = (bytes: Uint8Array<ArrayBuffer>, start: number): { value: bigint; size: number } | null => {
  let result = 0n;
  let shift = 0n;
  let byte = 0;
  for (let index = 0; index < 10; index += 1) {
    const pos = start + index;
    if (pos >= bytes.byteLength) return null;
    byte = bytes[pos] ?? 0;
    result |= BigInt(byte & 0x7f) << shift;
    shift += 7n;
    if ((byte & 0x80) === 0) {
      if (shift < 64n && (byte & 0x40) !== 0) {
        result |= (-1n) << shift;
      }
      return { value: result, size: index + 1 };
    }
  }
  return null;
};

const readEncodedPointer = (opts: {
  bytes: Uint8Array<ArrayBuffer>;
  dv: DataView;
  offset: number;
  encoding: number;
  littleEndian: boolean;
  pointerSize: 4 | 8;
  fieldVaddr: bigint;
  dataRelBase: bigint;
}): { value: bigint | null; size: number } | null => {
  if (opts.encoding === DW_EH_PE_omit) return { value: null, size: 0 };
  if (opts.encoding & DW_EH_PE_indirect) return null;

  const format = opts.encoding & 0x0f;
  const application = opts.encoding & 0x70;

  let raw: bigint;
  let size: number;
  if (format === DW_EH_PE_ptr) {
    size = opts.pointerSize;
    if (opts.offset + size > opts.dv.byteLength) return null;
    raw =
      size === 8
        ? opts.dv.getBigUint64(opts.offset, opts.littleEndian)
        : BigInt(opts.dv.getUint32(opts.offset, opts.littleEndian));
  } else if (format === DW_EH_PE_udata2) {
    size = 2;
    if (opts.offset + size > opts.dv.byteLength) return null;
    raw = BigInt(opts.dv.getUint16(opts.offset, opts.littleEndian));
  } else if (format === DW_EH_PE_udata4) {
    size = 4;
    if (opts.offset + size > opts.dv.byteLength) return null;
    raw = BigInt(opts.dv.getUint32(opts.offset, opts.littleEndian));
  } else if (format === DW_EH_PE_udata8) {
    size = 8;
    if (opts.offset + size > opts.dv.byteLength) return null;
    raw = opts.dv.getBigUint64(opts.offset, opts.littleEndian);
  } else if (format === DW_EH_PE_sdata2) {
    size = 2;
    if (opts.offset + size > opts.dv.byteLength) return null;
    raw = BigInt(opts.dv.getInt16(opts.offset, opts.littleEndian));
  } else if (format === DW_EH_PE_sdata4) {
    size = 4;
    if (opts.offset + size > opts.dv.byteLength) return null;
    raw = BigInt(opts.dv.getInt32(opts.offset, opts.littleEndian));
  } else if (format === DW_EH_PE_sdata8) {
    size = 8;
    if (opts.offset + size > opts.dv.byteLength) return null;
    raw = opts.dv.getBigInt64(opts.offset, opts.littleEndian);
  } else if (format === DW_EH_PE_uleb128) {
    const decoded = readUleb128(opts.bytes, opts.offset);
    if (!decoded) return null;
    raw = decoded.value;
    size = decoded.size;
  } else if (format === DW_EH_PE_sleb128) {
    const decoded = readSleb128(opts.bytes, opts.offset);
    if (!decoded) return null;
    raw = decoded.value;
    size = decoded.size;
  } else {
    return null;
  }

  let value = raw;
  if (application === DW_EH_PE_pcrel) {
    value = opts.fieldVaddr + raw;
  } else if (application === DW_EH_PE_datarel) {
    value = opts.dataRelBase + raw;
  } else if (application !== 0) {
    return null;
  }

  return { value, size };
};

const locateEhFrameHdr = (
  programHeaders: ElfProgramHeader[],
  sections: ElfSectionHeader[]
): { fileOffset: bigint; fileSize: bigint; vaddr: bigint } | null => {
  const ph = programHeaders.find(entry => entry.type === PT_GNU_EH_FRAME && entry.filesz > 0n);
  if (ph) return { fileOffset: ph.offset, fileSize: ph.filesz, vaddr: ph.vaddr };

  const sec = sections.find(entry => entry.name === ".eh_frame_hdr" && entry.size > 0n);
  if (!sec) return null;
  return { fileOffset: sec.offset, fileSize: sec.size, vaddr: sec.addr };
};

export async function collectElfDisassemblySeedsFromEhFrameHdr(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
}): Promise<ElfDisassemblySeedGroup[]> {
  const location = locateEhFrameHdr(opts.programHeaders, opts.sections);
  if (!location) return [];

  const start = toSafeIndex(location.fileOffset, ".eh_frame_hdr offset", opts.issues);
  const size = toSafeIndex(location.fileSize, ".eh_frame_hdr size", opts.issues);
  if (start == null || size == null || size <= 0) return [];
  const end = Math.min(opts.file.size, start + size);
  if (start >= opts.file.size || end <= start) return [];
  const bytes = new Uint8Array(await opts.file.slice(start, end).arrayBuffer());
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (dv.byteLength < 4) return [];

  const version = dv.getUint8(0);
  if (version !== 1) {
    opts.issues.push(`.eh_frame_hdr has unexpected version ${version}.`);
    return [];
  }
  const ehFramePtrEnc = dv.getUint8(1);
  const fdeCountEnc = dv.getUint8(2);
  const tableEnc = dv.getUint8(3);

  const pointerSize: 4 | 8 = opts.is64 ? 8 : 4;
  let cursor = 4;
  const dataRelBase = location.vaddr;

  const ehFramePtr = readEncodedPointer({
    bytes,
    dv,
    offset: cursor,
    encoding: ehFramePtrEnc,
    littleEndian: opts.littleEndian,
    pointerSize,
    fieldVaddr: location.vaddr + BigInt(cursor),
    dataRelBase
  });
  if (!ehFramePtr) {
    opts.issues.push(".eh_frame_hdr uses an unsupported eh_frame_ptr encoding.");
    return [];
  }
  cursor += ehFramePtr.size;

  const fdeCount = readEncodedPointer({
    bytes,
    dv,
    offset: cursor,
    encoding: fdeCountEnc,
    littleEndian: opts.littleEndian,
    pointerSize,
    fieldVaddr: location.vaddr + BigInt(cursor),
    dataRelBase
  });
  if (!fdeCount || fdeCount.value == null) {
    opts.issues.push(".eh_frame_hdr uses an unsupported fde_count encoding.");
    return [];
  }
  cursor += fdeCount.size;

  const decodedCount = Number(fdeCount.value);
  if (!Number.isSafeInteger(decodedCount) || decodedCount <= 0) return [];

  const vaddrs: bigint[] = [];
  for (let index = 0; index < decodedCount; index += 1) {
    const startPc = readEncodedPointer({
      bytes,
      dv,
      offset: cursor,
      encoding: tableEnc,
      littleEndian: opts.littleEndian,
      pointerSize,
      fieldVaddr: location.vaddr + BigInt(cursor),
      dataRelBase
    });
    if (!startPc) break;
    cursor += startPc.size;
    const fdePtr = readEncodedPointer({
      bytes,
      dv,
      offset: cursor,
      encoding: tableEnc,
      littleEndian: opts.littleEndian,
      pointerSize,
      fieldVaddr: location.vaddr + BigInt(cursor),
      dataRelBase
    });
    if (!fdePtr) break;
    cursor += fdePtr.size;

    if (startPc.value != null && startPc.value !== 0n) vaddrs.push(startPc.value);
  }

  if (vaddrs.length === 0) return [];
  return [{ source: ".eh_frame_hdr start PCs", vaddrs }];
}

