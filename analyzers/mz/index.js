"use strict";

import { collectPrintableRuns, readAsciiString } from "../../binary-utils.js";

const HEADER_SIZE = 0x40;
const DEFAULT_READ_LIMIT = 4096;

export async function parseMz(file) {
  const readLimit = Math.min(file.size || 0, DEFAULT_READ_LIMIT);
  const dv = new DataView(await file.slice(0, readLimit).arrayBuffer());
  if (dv.byteLength < 0x1c) return null;
  if (dv.getUint16(0, true) !== 0x5a4d) return null;

  const header = {
    e_magic: readAsciiString(dv, 0x00, 2),
    e_cblp: dv.getUint16(0x02, true),
    e_cp: dv.getUint16(0x04, true),
    e_crlc: dv.getUint16(0x06, true),
    e_cparhdr: dv.getUint16(0x08, true),
    e_minalloc: dv.getUint16(0x0a, true),
    e_maxalloc: dv.getUint16(0x0c, true),
    e_ss: dv.getUint16(0x0e, true),
    e_sp: dv.getUint16(0x10, true),
    e_csum: dv.getUint16(0x12, true),
    e_ip: dv.getUint16(0x14, true),
    e_cs: dv.getUint16(0x16, true),
    e_lfarlc: dv.getUint16(0x18, true),
    e_ovno: dv.getUint16(0x1a, true),
    e_res: [
      dv.getUint16(0x1c, true),
      dv.getUint16(0x1e, true),
      dv.getUint16(0x20, true),
      dv.getUint16(0x22, true)
    ],
    e_oemid: dv.getUint16(0x24, true),
    e_oeminfo: dv.getUint16(0x26, true),
    e_res2: Array.from({ length: 10 }, (_, index) => dv.getUint16(0x28 + index * 2, true)),
    e_lfanew: dv.byteLength >= HEADER_SIZE ? dv.getUint32(0x3c, true) : null
  };

  const payloadStart = header.e_cparhdr * 16;
  let stubStrings = [];
  if (payloadStart < dv.byteLength) {
    const stubLength = dv.byteLength - payloadStart;
    const sliceLength = Math.min(stubLength, 2048);
    if (sliceLength > 0) {
      const stubBytes = new Uint8Array(dv.buffer, payloadStart, sliceLength);
      stubStrings = collectPrintableRuns(stubBytes, 8).slice(0, 4);
    }
  }

  const relocations = [];
  const relocTableOff = header.e_lfarlc;
  const relocCount = header.e_crlc;
  if (relocTableOff && relocCount) {
    for (let index = 0; index < relocCount; index += 1) {
      const entryOffset = relocTableOff + index * 4;
      if (entryOffset + 4 > dv.byteLength) break;
      const off = dv.getUint16(entryOffset, true);
      const seg = dv.getUint16(entryOffset + 2, true);
      relocations.push({ index, segment: seg, offset: off });
    }
  }

  const warnings = [];
  if (header.e_lfanew != null && header.e_lfanew >= file.size) {
    warnings.push("e_lfanew points beyond file size");
  }
  if (relocations.length < relocCount) {
    warnings.push("Relocation table truncated");
  }

  return {
    signature: "MZ",
    header,
    payloadStart,
    relocations,
    stubStrings,
    warnings
  };
}
