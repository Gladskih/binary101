"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { coffSectionNameValue } from "./section-name.js";
import type { CoffSection } from "./types.js";
import {
  type CoffLineNumber,
  type CoffLineNumberBlock
} from "./debug-types.js";
import {
  COFF_LINE_NUMBER_FIELDS,
  COFF_LINE_NUMBER_RECORD_BYTE_LENGTH,
  readCoffField
} from "./layout.js";

export const parseCoffLineNumberBlock = async (
  reader: FileRangeReader,
  offset: number,
  count: number,
  addWarning: (message: string) => void
): Promise<CoffLineNumber[]> => {
  if (count === 0) return [];
  if (offset >= reader.size) {
    addWarning("COFF line-number table starts past end of file.");
    return [];
  }
  const requestedBytes = count * COFF_LINE_NUMBER_RECORD_BYTE_LENGTH;
  const availableBytes = Math.min(requestedBytes, Math.max(0, reader.size - offset));
  if (availableBytes < requestedBytes) addWarning("COFF line-number table is truncated.");
  const wholeRecordBytes =
    Math.floor(availableBytes / COFF_LINE_NUMBER_RECORD_BYTE_LENGTH) * COFF_LINE_NUMBER_RECORD_BYTE_LENGTH;
  const view = await reader.read(offset, wholeRecordBytes);
  return Array.from({ length: view.byteLength / COFF_LINE_NUMBER_RECORD_BYTE_LENGTH }, (_, index) => {
    const recordOffset = index * COFF_LINE_NUMBER_RECORD_BYTE_LENGTH;
    return {
      symbolTableIndexOrVirtualAddress: readCoffField(
        view,
        recordOffset,
        COFF_LINE_NUMBER_FIELDS.SymbolTableIndexOrVirtualAddress
      ),
      lineNumber: readCoffField(view, recordOffset, COFF_LINE_NUMBER_FIELDS.LineNumber)
    };
  });
};

const isLineNumberBlock = (block: CoffLineNumberBlock | null): block is CoffLineNumberBlock =>
  block !== null;

const parseSectionCoffLineNumberBlock = async (
  reader: FileRangeReader,
  section: CoffSection | undefined,
  index: number,
  addWarning: (message: string) => void
): Promise<CoffLineNumberBlock | null> => {
  const count = section?.numberOfLinenumbers ?? 0;
  const offset = section?.pointerToLinenumbers ?? 0;
  if (!section || count === 0 || offset === 0) return null;
  return {
    offset,
    sectionIndex: index + 1,
    sectionName: coffSectionNameValue(section.name),
    records: await parseCoffLineNumberBlock(reader, offset, count, addWarning)
  };
};

export const parseSectionCoffLineNumbers = async (
  reader: FileRangeReader,
  sections: CoffSection[],
  addWarning: (message: string) => void
): Promise<CoffLineNumberBlock[]> => {
  const blocks = await Promise.all(
    sections.map((section, index) => parseSectionCoffLineNumberBlock(reader, section, index, addWarning))
  );
  return blocks.filter(isLineNumberBlock);
};
