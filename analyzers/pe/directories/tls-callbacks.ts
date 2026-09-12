"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { RvaToOffset } from "../types.js";
import { toTlsRvaFromVa } from "./tls-addresses.js";

type TlsCallbacks = {
  rvas: number[];
  status: "absent" | "complete" | "incomplete";
};

const readCallbackPointer = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  entryRva: number,
  pointerSize: 4 | 8,
  warnings: string[]
): Promise<bigint | null> => {
  if (entryRva > PE_RVA_EXCLUSIVE_LIMIT - pointerSize) {
    warnings.push("TLS callback table exceeds the RVA address range before the null terminator.");
    return null;
  }
  const view = await readMappedRvaPrefix(reader, entryRva, pointerSize, rvaToOff);
  if (view.byteLength !== pointerSize) {
    warnings.push("TLS callback table is truncated or unmapped before the null terminator.");
    return null;
  }
  // Microsoft PE format, The TLS Directory: callback slots are pointer-sized VAs.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-directory
  return pointerSize === 4 ? BigInt(view.getUint32(0, true)) : view.getBigUint64(0, true);
};

export const readTlsCallbacks = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  tableVa: bigint,
  imageBase: bigint,
  pointerSize: 4 | 8,
  warnings: string[]
): Promise<TlsCallbacks> => {
  if (tableVa === 0n) return { rvas: [], status: "absent" };
  const tableRva = toTlsRvaFromVa(tableVa, imageBase);
  if (tableRva == null) {
    warnings.push(`TLS AddressOfCallBacks pointer 0x${tableVa.toString(16)} is not a valid VA.`);
    return { rvas: [], status: "incomplete" };
  }
  const rvas: number[] = [];
  let status: TlsCallbacks["status"] = "complete";
  for (let entryRva = tableRva; ; entryRva += pointerSize) {
    const pointer = await readCallbackPointer(reader, rvaToOff, entryRva, pointerSize, warnings);
    if (pointer == null) return { rvas, status: "incomplete" };
    if (pointer === 0n) return { rvas, status };
    const rva = toTlsRvaFromVa(pointer, imageBase);
    if (rva != null) rvas.push(rva);
    else {
      warnings.push(`TLS callback pointer 0x${pointer.toString(16)} is not a valid VA.`);
      status = "incomplete";
    }
  }
};
