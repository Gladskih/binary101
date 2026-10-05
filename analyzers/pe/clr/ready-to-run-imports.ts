import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { RvaToOffset } from "../types.js";
import type { PeClrReadyToRunImport } from "./ready-to-run-types.js";

// READYTORUN_IMPORT_SECTION has a 20-byte header followed by separate cells/signature RVAs.
// EntrySize == 0 means the target's pointer width (ReadyToRunReader.EnsureImportSectionsImpl).
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/readytorun.h#L159
const readImportHeader = (view: DataView, offset: number): PeClrReadyToRunImport => ({
  rva: view.getUint32(offset, true), size: view.getUint32(offset + 4, true),
  flags: view.getUint16(offset + 8, true), type: view.getUint8(offset + 10),
  entrySize: view.getUint8(offset + 11), signaturesRva: view.getUint32(offset + 12, true),
  auxiliaryDataRva: view.getUint32(offset + 16, true), entries: []
});

const appendCells = (
  table: PeClrReadyToRunImport, cells: DataView, signatures: DataView | null, width: number
): void => {
  for (let index = 0; index < Math.floor(cells.byteLength / width); index += 1) {
    const value = new Uint8Array(cells.buffer, cells.byteOffset + index * width, width);
    table.entries.push({ value,
      signatureRva: signatures && index * 4 + 4 <= signatures.byteLength
        ? signatures.getUint32(index * 4, true) : null });
  }
};

const readImportEntries = async (
  reader: FileRangeReader, mapper: RvaToOffset, table: PeClrReadyToRunImport,
  pointerSize: 4 | 8 | undefined, issues: Set<string>
): Promise<void> => {
  const width = table.entrySize || pointerSize;
  if (!width) {
    issues.add("ImportSections: zero EntrySize needs the target pointer width.");
    return;
  }
  if (table.size % width) issues.add("ImportSections: cell range ends with an incomplete entry.");
  const count = Math.floor(table.size / width);
  const cells = await readMappedRvaPrefix(reader, table.rva, count * width, mapper);
  const signatures = table.signaturesRva
    ? await readMappedRvaPrefix(reader, table.signaturesRva, count * 4, mapper) : null;
  if (cells.byteLength < count * width) issues.add("ImportSections: cell range is truncated.");
  if (signatures && signatures.byteLength < count * 4) {
    issues.add("ImportSections: signature RVA table is truncated.");
  }
  appendCells(table, cells, signatures, width);
};

export const parseReadyToRunImports = async (
  view: DataView, reader: FileRangeReader, mapper: RvaToOffset,
  pointerSize: 4 | 8 | undefined, issues: Set<string>
): Promise<PeClrReadyToRunImport[]> => {
  const imports: PeClrReadyToRunImport[] = [];
  if (view.byteLength % 20) issues.add("ImportSections: descriptor table is truncated.");
  for (let offset = 0; offset + 20 <= view.byteLength; offset += 20) {
    const table = readImportHeader(view, offset);
    imports.push(table);
    try {
      await readImportEntries(reader, mapper, table, pointerSize, issues);
    } catch {
      issues.add("ImportSections: import cells could not be read.");
    }
  }
  return imports;
};
