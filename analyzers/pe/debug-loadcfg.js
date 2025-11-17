"use strict";

import { toHex32 } from "../../binary-utils.js";

export async function parseDebugDirectory(file, dataDirs, rvaToOff, addCoverageRegion) {
  const debugDir = dataDirs.find(d => d.name === "DEBUG");
  if (!debugDir?.rva || debugDir.size < 28) return { entry: null, warning: null };
  const baseOffset = rvaToOff(debugDir.rva);
  if (baseOffset == null) return { entry: null, warning: "Debug directory RVA does not map to a file offset." };
  const fileSize = typeof file.size === "number" ? file.size : Infinity;
  if (baseOffset >= fileSize) return { entry: null, warning: "Debug directory starts past end of file." };
  const availableDirSize = Math.min(debugDir.size, Math.max(0, fileSize - baseOffset));
  addCoverageRegion("DEBUG directory", baseOffset, availableDirSize);
  const maxEntries = Math.min(16, Math.floor(availableDirSize / 28));
  if (maxEntries === 0) {
    return { entry: null, warning: "Debug directory is smaller than one entry; file may be truncated." };
  }
  let warning = availableDirSize < debugDir.size ? "Debug directory is shorter than recorded size (possible truncation)." : null;
  for (let index = 0; index < maxEntries; index++) {
    const entryOffset = baseOffset + index * 28;
    if (entryOffset + 28 > fileSize) {
      warning ??= "Debug directory extends beyond end of file (possible truncation).";
      break;
    }
    const view = new DataView(await file.slice(entryOffset, entryOffset + 28).arrayBuffer());
    if (view.byteLength < 24) {
      warning ??= "Debug directory entry is truncated.";
      break;
    }
    const type = view.getUint32(12, true);
    const dataSize = view.getUint32(16, true);
    const dataPointer = view.getUint32(20, true);
    const dataEnd = dataPointer + dataSize;
    if (type !== 2 || !dataPointer || dataSize < 24) continue;
    if (dataPointer >= fileSize || dataEnd > fileSize) {
      warning ??= "Debug directory points outside file bounds; file may be malformed.";
      continue;
    }
    const header = new DataView(await file.slice(dataPointer, dataPointer + dataSize).arrayBuffer());
    if (header.getUint32(0, true) !== 0x53445352) continue; // 'RSDS'
    const sig0 = header.getUint32(4, true);
    const sig1 = header.getUint16(8, true);
    const sig2 = header.getUint16(10, true);
    const sigTail = new Uint8Array(await file.slice(dataPointer + 12, dataPointer + 20).arrayBuffer());
    const guid =
      `${toHex32(sig0, 8).slice(2)}-${sig1.toString(16).padStart(4, "0")}-${sig2.toString(16).padStart(4, "0")}-` +
      `${[...sigTail.slice(0, 2)].map(b => b.toString(16).padStart(2, "0")).join("")}-` +
      `${[...sigTail.slice(2)].map(b => b.toString(16).padStart(2, "0")).join("")}`.toLowerCase();
    const age = new DataView(await file.slice(dataPointer + 20, dataPointer + 24).arrayBuffer()).getUint32(0, true);
    let path = "";
    let pos = dataPointer + 24;
    while (pos < dataPointer + dataSize && path.length < 1024) {
      const chunk = new Uint8Array(await file.slice(pos, pos + 64).arrayBuffer());
      const zeroIndex = chunk.indexOf(0);
      if (zeroIndex === -1) {
        path += String.fromCharCode(...chunk);
        pos += 64;
      } else {
        if (zeroIndex > 0) path += String.fromCharCode(...chunk.slice(0, zeroIndex));
        break;
      }
    }
    return { entry: { guid, age, path }, warning };
  }
  return { entry: null, warning };
}

export async function parseLoadConfigDirectory(file, dataDirs, rvaToOff, addCoverageRegion, isPlus) {
  const lcDir = dataDirs.find(d => d.name === "LOAD_CONFIG");
  if (!lcDir?.rva || lcDir.size < 0x40) return null;
  const base = rvaToOff(lcDir.rva);
  if (base == null) return null;
  addCoverageRegion("LOAD_CONFIG", base, lcDir.size);
  const view = new DataView(await file.slice(base, base + Math.min(lcDir.size, 0x200)).arrayBuffer());
  const Size = view.getUint32(0, true);
  const TimeDateStamp = view.getUint32(4, true);
  const Major = view.getUint16(8, true);
  const Minor = view.getUint16(10, true);
  let SecurityCookie = 0;
  let SEHandlerTable = 0;
  let SEHandlerCount = 0;
  let GuardCFFunctionTable = 0;
  let GuardCFFunctionCount = 0;
  let GuardFlags = 0;
  if (isPlus) {
    if (view.byteLength >= 0x78) {
      SecurityCookie = Number(view.getBigUint64(0x40, true));
      SEHandlerTable = Number(view.getBigUint64(0x58, true));
      SEHandlerCount = view.getUint32(0x60, true);
      GuardCFFunctionTable = Number(view.getBigUint64(0x68, true));
      GuardCFFunctionCount = view.getUint32(0x70, true);
      GuardFlags = view.getUint32(0x74, true);
    }
  } else if (view.byteLength >= 0x54) {
    SecurityCookie = view.getUint32(0x34, true);
    SEHandlerTable = view.getUint32(0x40, true);
    SEHandlerCount = view.getUint32(0x44, true);
    GuardCFFunctionTable = view.getUint32(0x48, true);
    GuardCFFunctionCount = view.getUint32(0x4c, true);
    GuardFlags = view.getUint32(0x50, true);
  }
  const saneCount = value =>
    Number.isFinite(value) && value >= 0 && value <= 10_000_000 ? value : 0;
  return {
    Size,
    TimeDateStamp,
    Major,
    Minor,
    SecurityCookie: SecurityCookie || 0,
    SEHandlerTable: SEHandlerTable || 0,
    SEHandlerCount: saneCount(SEHandlerCount),
    GuardCFFunctionTable: GuardCFFunctionTable || 0,
    GuardCFFunctionCount: saneCount(GuardCFFunctionCount),
    GuardFlags
  };
}
