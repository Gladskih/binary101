"use strict";

import { isRvaRange } from "../rva-mapping.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import {
  parseDynamicRelocationEntriesV132,
  parseDynamicRelocationEntriesV164,
  parseDynamicRelocationEntriesV232,
  parseDynamicRelocationEntriesV264
} from "./entry-parsers.js";
import { readLoadConfigPointerRva, type PeLoadConfig } from "../load-config/index.js";
import type { PeSection, RvaToOffset } from "../types.js";

const DYNAMIC_RELOCATION_TABLE_HEADER_SIZE = Uint32Array.BYTES_PER_ELEMENT * 2;

export type PeDynamicRelocationEntry =
  | { kind: "v1"; symbol: bigint; baseRelocSize: number; availableBytes: number }
  | {
      kind: "v2";
      headerSize: number;
      fixupInfoSize: number;
      symbol: bigint;
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

const resolveDynamicRelocTableRva = (
  fileSize: number,
  sections: PeSection[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  loadConfig: PeLoadConfig,
  warnings: string[]
): number | null => {
  const pointerRva =
    loadConfig.DynamicValueRelocTable !== 0n
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
        sectionOff = isRvaRange(section.virtualAddress + sectionOffset, 1)
          ? rvaToOff(section.virtualAddress + sectionOffset) : null;
      }
    }
  }

  const chooseInFileOffset = (candidate: number | null, source: string): number | null => {
    if (candidate == null) return null;
    if (!Number.isSafeInteger(candidate) || candidate < 0 || candidate >= fileSize) {
      warnings.push(`DynamicRelocations: ${source} offset 0x${(candidate >>> 0).toString(16)} is not in file.`);
      return null;
    }
    return candidate;
  };

  const pointerCandidate = chooseInFileOffset(pointerOff, "DynamicValueRelocTable");
  const sectionCandidate = chooseInFileOffset(sectionOff, "DynamicValueRelocTableSection/Offset");

  if (pointerCandidate != null && sectionCandidate != null && pointerCandidate !== sectionCandidate) {
    warnings.push(
      `DynamicRelocations: table offset mismatch (pointer=0x${pointerCandidate.toString(16)}, section=0x${sectionCandidate.toString(16)}).`
    );
  }

  if (pointerCandidate != null) return pointerRva;
  if (sectionCandidate != null) return sections[sectionIndex - 1]!.virtualAddress + sectionOffset;
  if (loadConfig.DynamicValueRelocTable !== 0n || sectionIndex > 0) {
    warnings.push("DynamicRelocations: table address does not map to file data.");
  }
  return null;
};

const readDynamicRelocationTable = async (
  reader: FileRangeReader,
  tableRva: number,
  rvaToOff: RvaToOffset,
  warnings: string[]
): Promise<{ version: number; dataSize: number; dataEnd: number; view: DataView }> => {
  const header = await readMappedRvaPrefix(reader, tableRva,
    DYNAMIC_RELOCATION_TABLE_HEADER_SIZE, rvaToOff);
  if (header.byteLength < DYNAMIC_RELOCATION_TABLE_HEADER_SIZE) {
    warnings.push("DynamicRelocations: truncated header.");
    return { version: 0, dataSize: 0, dataEnd: 0, view: new DataView(new ArrayBuffer(0)) };
  }
  const version = header.getUint32(0, true);
  const dataSize = header.getUint32(Uint32Array.BYTES_PER_ELEMENT, true);
  const readableSize = Math.min(
    DYNAMIC_RELOCATION_TABLE_HEADER_SIZE + dataSize,
    reader.size
  );
  const view = await readMappedRvaPrefix(reader, tableRva, readableSize, rvaToOff);
  const dataEnd = Math.min(view.byteLength, DYNAMIC_RELOCATION_TABLE_HEADER_SIZE + dataSize);

  if (dataEnd < DYNAMIC_RELOCATION_TABLE_HEADER_SIZE + dataSize) {
    warnings.push(`DynamicRelocations: declared size 0x${dataSize.toString(16)} is truncated by EOF.`);
  }

  return { version, dataSize, dataEnd, view };
};

const parseDynamicRelocationsWithVariant = async (
  reader: FileRangeReader,
  sections: PeSection[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
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
  const tableOffset = resolveDynamicRelocTableRva(
    reader.size,
    sections,
    rvaToOff,
    imageBase,
    loadConfig,
    warnings
  );
  if (tableOffset == null) return warnings.length
    ? { version: 0, dataSize: 0, entries: [], warnings } : null;

  const { version, dataSize, dataEnd, view } = await readDynamicRelocationTable(
    reader,
    tableOffset,
    rvaToOff,
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
  reader: FileRangeReader,
  sections: PeSection[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  loadConfig: PeLoadConfig
): Promise<PeDynamicRelocations | null> =>
  parseDynamicRelocationsWithVariant(
    reader,
    sections,
    rvaToOff,
    imageBase,
    loadConfig,
    parseDynamicRelocationEntriesV132,
    parseDynamicRelocationEntriesV232
  );

export const parseDynamicRelocationsFromLoadConfig64 = async (
  reader: FileRangeReader,
  sections: PeSection[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  loadConfig: PeLoadConfig
): Promise<PeDynamicRelocations | null> =>
  parseDynamicRelocationsWithVariant(
    reader,
    sections,
    rvaToOff,
    imageBase,
    loadConfig,
    parseDynamicRelocationEntriesV164,
    parseDynamicRelocationEntriesV264
  );
