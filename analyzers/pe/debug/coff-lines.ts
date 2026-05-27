"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { peSectionNameValue } from "../sections/name.js";
import type { PeSection } from "../types.js";
import {
  IMAGE_LINENUMBER_SIZE,
  type PeCoffLineNumber,
  type PeCoffLineNumberBlock
} from "./coff-types.js";

export const parseCoffLineNumberBlock = async (
  reader: FileRangeReader,
  offset: number,
  count: number,
  addWarning: (message: string) => void
): Promise<PeCoffLineNumber[]> => {
  if (count === 0) return [];
  if (offset >= reader.size) {
    addWarning("COFF line-number table starts past end of file.");
    return [];
  }
  const requestedBytes = count * IMAGE_LINENUMBER_SIZE;
  const availableBytes = Math.min(requestedBytes, Math.max(0, reader.size - offset));
  if (availableBytes < requestedBytes) addWarning("COFF line-number table is truncated.");
  const wholeRecordBytes = Math.floor(availableBytes / IMAGE_LINENUMBER_SIZE) * IMAGE_LINENUMBER_SIZE;
  const view = await reader.read(offset, wholeRecordBytes);
  return Array.from({ length: view.byteLength / IMAGE_LINENUMBER_SIZE }, (_, index) => ({
    symbolTableIndexOrVirtualAddress: view.getUint32(index * IMAGE_LINENUMBER_SIZE, true),
    lineNumber: view.getUint16(index * IMAGE_LINENUMBER_SIZE + 4, true)
  }));
};

export const parseSectionCoffLineNumbers = async (
  reader: FileRangeReader,
  sections: PeSection[],
  addWarning: (message: string) => void
): Promise<PeCoffLineNumberBlock[]> => {
  const blocks: PeCoffLineNumberBlock[] = [];
  for (let index = 0; index < sections.length; index += 1) {
    const section = sections[index];
    const count = section?.numberOfLinenumbers ?? 0;
    const offset = section?.pointerToLinenumbers ?? 0;
    if (!section || count === 0 || offset === 0) continue;
    blocks.push({
      offset,
      sectionIndex: index + 1,
      sectionName: peSectionNameValue(section.name),
      records: await parseCoffLineNumberBlock(reader, offset, count, addWarning)
    });
  }
  return blocks;
};
