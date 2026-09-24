"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { isRvaRange } from "../rva-mapping.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { RvaToOffset } from "../types.js";
import type { PeIatDirectory } from "../imports/iat.js";
import type { PeImportParseResult } from "../imports/index.js";
import type { PeControlTransferRecord } from "./control-transfers.js";
import type { PeDynamicRelocations } from "./index.js";

type ImportLink = NonNullable<Extract<PeControlTransferRecord, { kind: "import" }>["importLink"]>;

const buildImportSlotLinks = (imports: PeImportParseResult): Map<number, ImportLink | null> => {
  const links = new Map<number, ImportLink | null>();
  for (const [entryIndex, entry] of imports.entries.entries()) {
    for (const [index, fn] of entry.functions.entries()) {
      const slotRva = entry.firstThunkRva + index * imports.thunkEntrySize;
      if (!entry.dll || (!fn.name && fn.ordinal == null) ||
        !isRvaRange(slotRva, imports.thunkEntrySize)) continue;
      links.set(slotRva, links.has(slotRva) ? null : { entryIndex, functionIndex: index });
    }
  }
  return links;
};

const resolveImportLink = async (
  record: Extract<PeControlTransferRecord, { kind: "import" }>,
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  iat: PeIatDirectory,
  slotLinks: Map<number, ImportLink | null>
): Promise<ImportLink | null> => {
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
  const link = slotLinks.get(slotRva);
  if (!link) return null;
  const view = await readMappedRvaPrefix(reader, record.rva, 7, rvaToOff);
  if (view.byteLength < 6) return null;
  const prefixSize = (view.getUint8(0) & 0xf0) === 0x40 ? 1 : 0;
  if (view.byteLength < prefixSize + 6 || view.getUint8(prefixSize) !== 0xff) return null;
  if (view.getUint8(prefixSize + 1) !== (record.indirectCall ? 0x15 : 0x25)) return null;
  const targetRva = record.rva + prefixSize + 6 + view.getInt32(prefixSize + 2, true);
  return targetRva === slotRva ? link : null;
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
  const slotLinks = buildImportSlotLinks(imports);
  if (!slotLinks.size) return relocations;
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
        let link: ImportLink | null = null;
        try {
          link = await resolveImportLink(record, reader, rvaToOff, iat, slotLinks);
        } catch {
          readFailed = true;
        }
        if (link) changed = true;
        controlTransfers.push(link ? { ...record, importLink: link } : record);
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
