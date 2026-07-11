"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { readMappedNullTerminatedAsciiString } from "../strings/mapped-ascii-string.js";
import {
  addReferenceMessage,
  PE32_POINTER_BYTES,
  readMappedReferenceTable,
  readMappedReferenceView,
  referencePointerRva,
  type PeRvaMapping,
  type PePointerBytes,
} from "./reference-reader.js";
import type { PeEnclaveConfiguration, PeEnclaveImport } from "./reference-types.js";

// Microsoft Windows SDK IMAGE_ENCLAVE_CONFIG32/64 and IMAGE_ENCLAVE_IMPORT.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_enclave_config32
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_enclave_config64
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_enclave_import
type EnclaveConfigLayout = Readonly<{
  minimumSize: number;
  fullSize: number;
  numberOfThreads: number;
  enclaveFlags: number;
}>;
const CONFIG32_LAYOUT: EnclaveConfigLayout = {
  minimumSize: 72, fullSize: 76, numberOfThreads: 68, enclaveFlags: 72
};
const CONFIG64_LAYOUT: EnclaveConfigLayout = {
  minimumSize: 76, fullSize: 80, numberOfThreads: 72, enclaveFlags: 76
};
const CONFIG_OFFSETS = {
  size: 0, minimumRequiredConfigSize: 4, policyFlags: 8, numberOfImports: 12,
  importList: 16, importEntrySize: 20, familyId: 24, imageId: 40,
  imageVersion: 56, securityVersion: 60, enclaveSize: 64
} as const;
const IMPORT_SIZE = 80;
const IMPORT_OFFSETS = {
  matchType: 0, minimumSecurityVersion: 4, uniqueOrAuthorId: 8,
  familyId: 40, imageId: 56, importName: 72, reserved: 76
} as const;
const LONG_ID_SIZE = 32;
const SHORT_ID_SIZE = 16;

const matchTypeName = (matchType: number): PeEnclaveImport["matchType"] => {
  if (matchType === 0) return "NONE";
  if (matchType === 1) return "UNIQUE_ID";
  if (matchType === 2) return "AUTHOR_ID";
  if (matchType === 3) return "FAMILY_ID";
  if (matchType === 4) return "IMAGE_ID";
  return "UNKNOWN";
};

const readImportName = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  nameRva: number,
  index: number
): Promise<string | undefined> => {
  if (nameRva === 0) return undefined;
  if (!mapping.rawSpan(nameRva)) {
    addReferenceMessage(notes,
      `LOAD_CONFIG: Enclave import ${index} name RVA 0x${nameRva.toString(16)} is not backed by raw file data.`);
    return undefined;
  }
  let text = "";
  let cursorRva = nameRva;
  for (let span = mapping.rawSpan(cursorRva); span; span = mapping.rawSpan(cursorRva)) {
    const result = await readMappedNullTerminatedAsciiString(
      reader, reader.size, mapping.offset, cursorRva, span[1]
    );
    if (!result) return text || undefined;
    text += result.text;
    if (result.terminated) return text;
    cursorRva += span[1];
  }
  addReferenceMessage(warnings, `LOAD_CONFIG: Enclave import ${index} name is not null-terminated.`);
  return text;
};

const bytesAt = (view: DataView, offset: number, size: number): number[] =>
  Array.from(new Uint8Array(view.buffer, view.byteOffset + offset, size));

const parseImport = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  view: DataView,
  offset: number,
  index: number
): Promise<PeEnclaveImport> => {
  const nameRva = view.getUint32(offset + IMPORT_OFFSETS.importName, true);
  const name = await readImportName(
    reader, mapping, warnings, notes, nameRva, index
  );
  return {
    matchType: matchTypeName(view.getUint32(offset, true)),
    minimumSecurityVersion: view.getUint32(offset + IMPORT_OFFSETS.minimumSecurityVersion, true),
    uniqueOrAuthorId: bytesAt(view, offset + IMPORT_OFFSETS.uniqueOrAuthorId, LONG_ID_SIZE),
    familyId: bytesAt(view, offset + IMPORT_OFFSETS.familyId, SHORT_ID_SIZE),
    imageId: bytesAt(view, offset + IMPORT_OFFSETS.imageId, SHORT_ID_SIZE),
    nameRva,
    ...(name === undefined ? {} : { name }),
    reserved: view.getUint32(offset + IMPORT_OFFSETS.reserved, true)
  };
};

const parseImports = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  listRva: number,
  count: number,
  entrySize: number
): Promise<PeEnclaveImport[]> => {
  if (entrySize < IMPORT_SIZE) {
    addReferenceMessage(warnings,
      `LOAD_CONFIG: Enclave ImportEntrySize ${entrySize} is smaller than IMAGE_ENCLAVE_IMPORT.`);
    return [];
  }
  const view = await readMappedReferenceTable(
    reader, mapping, warnings, notes, "Enclave import list", listRva, count, entrySize
  );
  if (!view) return [];
  return Promise.all(Array.from({ length: count }, (_, index) => parseImport(
    reader, mapping, warnings, notes, view, index * entrySize, index
  )));
};

const validateDeclaredSize = (
  mapping: PeRvaMapping,
  warnings: string[],
  rva: number,
  size: number
): void => {
  if (mapping.rawSpan(rva) && !mapping.rawChunks(rva, size)) {
    addReferenceMessage(warnings, "LOAD_CONFIG: Enclave configuration declared Size extends beyond raw file data.");
  }
};

const buildConfiguration = (
  view: DataView,
  fullView: DataView | null,
  layout: EnclaveConfigLayout,
  rva: number,
  size: number,
  isPe32: boolean,
  imports: PeEnclaveImport[]
): PeEnclaveConfiguration => ({
  rva,
  size,
  minimumRequiredConfigSize: view.getUint32(CONFIG_OFFSETS.minimumRequiredConfigSize, true),
  policyFlags: view.getUint32(CONFIG_OFFSETS.policyFlags, true),
  numberOfImports: view.getUint32(CONFIG_OFFSETS.numberOfImports, true),
  importListRva: view.getUint32(CONFIG_OFFSETS.importList, true),
  importEntrySize: view.getUint32(CONFIG_OFFSETS.importEntrySize, true),
  familyId: bytesAt(view, CONFIG_OFFSETS.familyId, SHORT_ID_SIZE),
  imageId: bytesAt(view, CONFIG_OFFSETS.imageId, SHORT_ID_SIZE),
  imageVersion: view.getUint32(CONFIG_OFFSETS.imageVersion, true),
  securityVersion: view.getUint32(CONFIG_OFFSETS.securityVersion, true),
  enclaveSize: isPe32
    ? BigInt(view.getUint32(CONFIG_OFFSETS.enclaveSize, true))
    : view.getBigUint64(CONFIG_OFFSETS.enclaveSize, true),
  numberOfThreads: view.getUint32(layout.numberOfThreads, true),
  ...(fullView ? { enclaveFlags: fullView.getUint32(layout.enclaveFlags, true) } : {}),
  imports
});

export const parseEnclaveConfiguration = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  imageBase: bigint,
  pointerBytes: PePointerBytes,
  warnings: string[],
  notes: string[],
  pointerVa: bigint
): Promise<PeEnclaveConfiguration | null> => {
  const rva = referencePointerRva(imageBase, warnings, "EnclaveConfigurationPointer", pointerVa);
  if (rva == null) return null;
  const isPe32 = pointerBytes === PE32_POINTER_BYTES;
  const layout = isPe32 ? CONFIG32_LAYOUT : CONFIG64_LAYOUT;
  const minimumView = await readMappedReferenceView(
    reader, mapping, warnings, notes, "Enclave configuration header", rva, layout.minimumSize
  );
  if (!minimumView) return null;
  const size = minimumView.getUint32(CONFIG_OFFSETS.size, true);
  if (size < layout.minimumSize) {
    addReferenceMessage(warnings, `LOAD_CONFIG: Enclave configuration Size 0x${size.toString(16)} is too small.`);
    return null;
  }
  validateDeclaredSize(mapping, warnings, rva, size);
  if (size > layout.fullSize) {
    addReferenceMessage(notes,
      `LOAD_CONFIG: Enclave configuration has ${size - layout.fullSize} extension bytes with no known layout.`);
  }
  const fullView = size >= layout.fullSize ? await readMappedReferenceView(
    reader, mapping, warnings, notes, "Enclave configuration", rva, layout.fullSize
  ) : null;
  const view = fullView ?? minimumView;
  const numberOfImports = view.getUint32(CONFIG_OFFSETS.numberOfImports, true);
  const importListRva = view.getUint32(CONFIG_OFFSETS.importList, true);
  const importEntrySize = view.getUint32(CONFIG_OFFSETS.importEntrySize, true);
  const imports = await parseImports(
    reader, mapping, warnings, notes, importListRva, numberOfImports, importEntrySize
  );
  return buildConfiguration(view, fullView, layout, rva, size, isPe32, imports);
};
