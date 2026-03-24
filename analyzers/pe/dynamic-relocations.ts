"use strict";

import {
  parseDynamicRelocationEntriesV132,
  parseDynamicRelocationEntriesV164,
  parseDynamicRelocationEntriesV232,
  parseDynamicRelocationEntriesV264
} from "./dynamic-relocation-entry-parsers.js";
import { readLoadConfigPointerRva, type PeLoadConfig } from "./load-config.js";
import type { PeSection, RvaToOffset } from "./types.js";

const DYNAMIC_RELOCATION_TABLE_HEADER_SIZE = Uint32Array.BYTES_PER_ELEMENT * 2;

export type PeDynamicRelocationEntry =
  | { kind: "v1"; symbol: number | bigint; baseRelocSize: number; availableBytes: number }
  | {
      kind: "v2";
      headerSize: number;
      fixupInfoSize: number;
      symbol: number | bigint;
      symbolGroup: number;
      flags: number;
      availableBytes: number;
    };

export type PeDynamicRelocations = {
  version: number;
  dataSize: number;
  entries: PeDynamicRelocationEntry[];
  warnings?: string[];
};

const resolveDynamicRelocTableOffset = (
  fileSize: number,
  sections: PeSection[],
  rvaToOff: RvaToOffset,
  imageBase: number,
  loadConfig: PeLoadConfig,
  warnings: string[]
): number | null => {
  const pointerRva =
    loadConfig.DynamicValueRelocTable && Number.isSafeInteger(imageBase)
      ? readLoadConfigPointerRva(imageBase, loadConfig.DynamicValueRelocTable)
      : null;
  const pointerOff = pointerRva != null ? rvaToOff(pointerRva) : null;

  const sectionIndex = Number.isSafeInteger(loadConfig.DynamicValueRelocTableSection)
    ? loadConfig.DynamicValueRelocTableSection
    : 0;
  const sectionOffset = Number.isSafeInteger(loadConfig.DynamicValueRelocTableOffset)
    ? loadConfig.DynamicValueRelocTableOffset
    : 0;

  let sectionOff: number | null = null;
  if (sectionIndex > 0) {
    if (sectionIndex > sections.length) {
      warnings.push(
        `DynamicRelocations: DynamicValueRelocTableSection=${sectionIndex} is out of range (sections=${sections.length}).`
      );
    } else {
      const section = sections[sectionIndex - 1];
      if (!section) {
        warnings.push(
          `DynamicRelocations: DynamicValueRelocTableSection=${sectionIndex} does not map to a section header.`
        );
      } else {
        sectionOff = rvaToOff((section.virtualAddress + sectionOffset) >>> 0);
        if (sectionOff == null && Number.isSafeInteger(section.pointerToRawData)) {
          sectionOff = (section.pointerToRawData + sectionOffset) >>> 0;
        }
      }
    }
  }

  const chooseInFileOffset = (candidate: number | null, source: string): number | null => {
    if (candidate == null) return null;
    if (!Number.isSafeInteger(candidate) || candidate < 0 || candidate >= fileSize) {
      warnings.push(`DynamicRelocations: ${source} offset 0x${(candidate >>> 0).toString(16)} is not in file.`);
      return null;
    }
    return candidate >>> 0;
  };

  const pointerCandidate = chooseInFileOffset(pointerOff, "DynamicValueRelocTable");
  const sectionCandidate = chooseInFileOffset(sectionOff, "DynamicValueRelocTableSection/Offset");

  if (pointerCandidate != null && sectionCandidate != null && pointerCandidate !== sectionCandidate) {
    warnings.push(
      `DynamicRelocations: table offset mismatch (pointer=0x${pointerCandidate.toString(16)}, section=0x${sectionCandidate.toString(16)}).`
    );
  }

  return pointerCandidate ?? sectionCandidate;
};

const readDynamicRelocationTable = async (
  file: File,
  tableOffset: number,
  warnings: string[]
): Promise<{ version: number; dataSize: number; dataEnd: number; view: DataView }> => {
  if (file.size - tableOffset < DYNAMIC_RELOCATION_TABLE_HEADER_SIZE) {
    warnings.push("DynamicRelocations: truncated header.");
    return { version: 0, dataSize: 0, dataEnd: 0, view: new DataView(new ArrayBuffer(0)) };
  }

  const header = new DataView(
    await file.slice(tableOffset, tableOffset + DYNAMIC_RELOCATION_TABLE_HEADER_SIZE).arrayBuffer()
  );
  const version = header.getUint32(0, true);
  const dataSize = header.getUint32(Uint32Array.BYTES_PER_ELEMENT, true);
  const readableSize = Math.min(
    DYNAMIC_RELOCATION_TABLE_HEADER_SIZE + dataSize,
    Math.max(0, file.size - tableOffset)
  );
  const view = new DataView(await file.slice(tableOffset, tableOffset + readableSize).arrayBuffer());
  const dataEnd = Math.min(view.byteLength, DYNAMIC_RELOCATION_TABLE_HEADER_SIZE + dataSize);

  if (dataEnd < DYNAMIC_RELOCATION_TABLE_HEADER_SIZE + dataSize) {
    warnings.push(`DynamicRelocations: declared size 0x${dataSize.toString(16)} is truncated by EOF.`);
  }

  return { version, dataSize, dataEnd, view };
};

const parseDynamicRelocationsWithVariant = async (
  file: File,
  sections: PeSection[],
  rvaToOff: RvaToOffset,
  imageBase: number,
  loadConfig: PeLoadConfig,
  parseVersion1: (
    view: DataView,
    dataEnd: number,
    warnings: string[]
  ) => PeDynamicRelocationEntry[],
  parseVersion2: (
    view: DataView,
    dataEnd: number,
    warnings: string[]
  ) => PeDynamicRelocationEntry[]
): Promise<PeDynamicRelocations | null> => {
  const warnings: string[] = [];
  const tableOffset = resolveDynamicRelocTableOffset(
    file.size,
    sections,
    rvaToOff,
    imageBase,
    loadConfig,
    warnings
  );
  if (tableOffset == null) return null;

  const { version, dataSize, dataEnd, view } = await readDynamicRelocationTable(
    file,
    tableOffset,
    warnings
  );

  const entries =
    version === 1
      ? parseVersion1(view, dataEnd, warnings)
      : version === 2
        ? parseVersion2(view, dataEnd, warnings)
        : (warnings.push(`DynamicRelocations: unsupported version ${version}.`), []);

  return {
    version,
    dataSize,
    entries,
    ...(warnings.length ? { warnings } : {})
  };
};

export const parseDynamicRelocationsFromLoadConfig32 = async (
  file: File,
  sections: PeSection[],
  rvaToOff: RvaToOffset,
  imageBase: number,
  loadConfig: PeLoadConfig
): Promise<PeDynamicRelocations | null> =>
  parseDynamicRelocationsWithVariant(
    file,
    sections,
    rvaToOff,
    imageBase,
    loadConfig,
    parseDynamicRelocationEntriesV132,
    parseDynamicRelocationEntriesV232
  );

export const parseDynamicRelocationsFromLoadConfig64 = async (
  file: File,
  sections: PeSection[],
  rvaToOff: RvaToOffset,
  imageBase: number,
  loadConfig: PeLoadConfig
): Promise<PeDynamicRelocations | null> =>
  parseDynamicRelocationsWithVariant(
    file,
    sections,
    rvaToOff,
    imageBase,
    loadConfig,
    parseDynamicRelocationEntriesV164,
    parseDynamicRelocationEntriesV264
  );
