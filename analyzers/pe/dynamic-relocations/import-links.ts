"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { isRvaRange } from "../rva-mapping.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { RvaToOffset } from "../types.js";
import type { PeIatDirectory } from "../imports/iat.js";
import type { PeImportParseResult } from "../imports/index.js";
import type { PeControlTransferRecord } from "./control-transfers.js";
import type { PeDynamicRelocations } from "./index.js";

const buildImportSlotNames = (imports: PeImportParseResult): Map<number, string | null> => {
  const names = new Map<number, string | null>();
  for (const entry of imports.entries) {
    for (const [index, fn] of entry.functions.entries()) {
      const slotRva = entry.firstThunkRva + index * imports.thunkEntrySize;
      const name = fn.name || (fn.ordinal != null ? `#${fn.ordinal}` : "");
      if (!entry.dll || !name || !isRvaRange(slotRva, imports.thunkEntrySize)) continue;
      names.set(slotRva, names.has(slotRva) ? null : `${entry.dll}!${name}`);
    }
  }
  return names;
};

const resolveImportName = async (
  record: Extract<PeControlTransferRecord, { kind: "import" }>,
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  iat: PeIatDirectory,
  slotNames: Map<number, string | null>
): Promise<string | null> => {
  // Windows SDK winnt.h calls this IATIndex; PE32+ import thunks are 8 bytes.
  // https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
  // x64 FF /2 and FF /4 with ModRM 15/25 are RIP-relative CALL/JMP [disp32].
  // https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
  // Require the original instruction to point to the same indexed IAT slot.
  const slotOffset = record.iatIndex * 8;
  if (!Number.isSafeInteger(slotOffset) || slotOffset < 0 || slotOffset + 8 > iat.size ||
    !isRvaRange(record.rva, 1)) return null;
  const slotRva = iat.rva + slotOffset;
  if (!isRvaRange(slotRva, 8)) return null;
  const name = slotNames.get(slotRva);
  if (!name) return null;
  const view = await readMappedRvaPrefix(reader, record.rva, 7, rvaToOff);
  if (view.byteLength < 6) return null;
  const prefixSize = (view.getUint8(0) & 0xf0) === 0x40 ? 1 : 0;
  if (view.byteLength < prefixSize + 6 || view.getUint8(prefixSize) !== 0xff) return null;
  if (view.getUint8(prefixSize + 1) !== (record.indirectCall ? 0x15 : 0x25)) return null;
  const targetRva = record.rva + prefixSize + 6 + view.getInt32(prefixSize + 2, true);
  return targetRva === slotRva ? name : null;
};

export const linkDynamicImportControlTransfers = async (
  relocations: PeDynamicRelocations,
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  iat: PeIatDirectory | null,
  imports: PeImportParseResult
): Promise<PeDynamicRelocations> => {
  if (!iat || iat.warnings?.length || !isRvaRange(iat.rva, iat.size) ||
    imports.thunkEntrySize !== 8) return relocations;
  const slotNames = buildImportSlotNames(imports);
  if (!slotNames.size) return relocations;
  let changed = false;
  let readFailed = false;
  const entries = [];
  for (const entry of relocations.entries) {
    if (!entry.controlTransfers) {
      entries.push(entry);
      continue;
    }
    const controlTransfers: PeControlTransferRecord[] = [];
    for (const record of entry.controlTransfers) {
      if (record.kind === "import") {
        let name: string | null = null;
        try {
          name = await resolveImportName(record, reader, rvaToOff, iat, slotNames);
        } catch {
          readFailed = true;
        }
        if (name) changed = true;
        controlTransfers.push(name ? { ...record, importName: name } : record);
      } else {
        controlTransfers.push(record);
      }
    }
    entries.push({ ...entry, controlTransfers });
  }
  return changed || readFailed ? { ...relocations, entries,
    ...(readFailed ? { warnings: [...(relocations.warnings ?? []),
      "DynamicRelocations: could not read an import control-transfer instruction."] } : {})
  } : relocations;
};
