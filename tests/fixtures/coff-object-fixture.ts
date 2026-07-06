"use strict";

import {
  COFF_FILE_HEADER_BYTE_LENGTH,
  COFF_FILE_HEADER_FIELDS,
  COFF_RELOCATION_FIELDS,
  COFF_RELOCATION_RECORD_BYTE_LENGTH,
  COFF_SECTION_CHARACTERISTICS,
  COFF_SECTION_HEADER_BYTE_LENGTH,
  COFF_SECTION_HEADER_FIELDS,
  COFF_SHORT_NAME_BYTE_LENGTH,
  COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH,
  COFF_SYMBOL_FIELDS,
  COFF_SYMBOL_RECORD_BYTE_LENGTH,
  type CoffNumericField
} from "../../analyzers/coff/layout.js";
import { IMAGE_FILE_MACHINE_I386 } from "../../analyzers/coff/machine.js";
import { COFF_I386_RELOCATION_TYPES } from "../../analyzers/coff/relocation-types.js";
import { COFF_STORAGE_CLASS } from "../../analyzers/coff/storage-classes.js";
import { MockFile } from "../helpers/mock-file.js";

const SECTION_COUNT = 1;
const COFF_SYMBOL_RECORD_COUNT = 3;
const SECTION_RAW_BYTE_LENGTH = 4;
const TEXT_SECTION_CHARACTERISTICS =
  COFF_SECTION_CHARACTERISTICS.CNT_CODE |
  COFF_SECTION_CHARACTERISTICS.MEM_EXECUTE |
  COFF_SECTION_CHARACTERISTICS.MEM_READ;
const SECTION_RAW_OFFSET = COFF_FILE_HEADER_BYTE_LENGTH + COFF_SECTION_HEADER_BYTE_LENGTH * SECTION_COUNT;
const SECTION_RELOCATION_OFFSET = SECTION_RAW_OFFSET + SECTION_RAW_BYTE_LENGTH;
const SYMBOL_TABLE_OFFSET = SECTION_RELOCATION_OFFSET + COFF_RELOCATION_RECORD_BYTE_LENGTH;
const STRING_TABLE_OFFSET = SYMBOL_TABLE_OFFSET + COFF_SYMBOL_RECORD_BYTE_LENGTH * COFF_SYMBOL_RECORD_COUNT;

const writeAscii = (bytes: Uint8Array, offset: number, text: string, maxLength: number): void => {
  bytes.set(new TextEncoder().encode(text).subarray(0, maxLength), offset);
};

const writeCoffField = (
  view: DataView,
  recordOffset: number,
  field: CoffNumericField,
  value: number
): void => {
  const offset = recordOffset + field.offset;
  if (field.width === "u8") {
    view.setUint8(offset, value);
    return;
  }
  if (field.width === "u16") {
    view.setUint16(offset, value, true);
    return;
  }
  if (field.width === "i16") {
    view.setInt16(offset, value, true);
    return;
  }
  view.setUint32(offset, value, true);
};

const writeCoffHeader = (view: DataView): void => {
  writeCoffField(view, 0, COFF_FILE_HEADER_FIELDS.Machine, IMAGE_FILE_MACHINE_I386);
  writeCoffField(view, 0, COFF_FILE_HEADER_FIELDS.NumberOfSections, SECTION_COUNT);
  writeCoffField(view, 0, COFF_FILE_HEADER_FIELDS.PointerToSymbolTable, SYMBOL_TABLE_OFFSET);
  writeCoffField(view, 0, COFF_FILE_HEADER_FIELDS.NumberOfSymbols, COFF_SYMBOL_RECORD_COUNT);
  writeCoffField(view, 0, COFF_FILE_HEADER_FIELDS.SizeOfOptionalHeader, 0);
};

const writeTextSectionHeader = (bytes: Uint8Array, view: DataView): void => {
  writeAscii(bytes, COFF_FILE_HEADER_BYTE_LENGTH, ".text", COFF_SHORT_NAME_BYTE_LENGTH);
  writeCoffField(
    view,
    COFF_FILE_HEADER_BYTE_LENGTH,
    COFF_SECTION_HEADER_FIELDS.SizeOfRawData,
    SECTION_RAW_BYTE_LENGTH
  );
  writeCoffField(view, COFF_FILE_HEADER_BYTE_LENGTH, COFF_SECTION_HEADER_FIELDS.PointerToRawData, SECTION_RAW_OFFSET);
  writeCoffField(
    view,
    COFF_FILE_HEADER_BYTE_LENGTH,
    COFF_SECTION_HEADER_FIELDS.PointerToRelocations,
    SECTION_RELOCATION_OFFSET
  );
  writeCoffField(view, COFF_FILE_HEADER_BYTE_LENGTH, COFF_SECTION_HEADER_FIELDS.NumberOfRelocations, 1);
  writeCoffField(
    view,
    COFF_FILE_HEADER_BYTE_LENGTH,
    COFF_SECTION_HEADER_FIELDS.Characteristics,
    TEXT_SECTION_CHARACTERISTICS
  );
};

const writeRelocation = (view: DataView): void => {
  writeCoffField(view, SECTION_RELOCATION_OFFSET, COFF_RELOCATION_FIELDS.VirtualAddress, 0);
  writeCoffField(view, SECTION_RELOCATION_OFFSET, COFF_RELOCATION_FIELDS.SymbolTableIndex, 2);
  writeCoffField(view, SECTION_RELOCATION_OFFSET, COFF_RELOCATION_FIELDS.Type, COFF_I386_RELOCATION_TYPES.REL32);
};

const writeSymbols = (bytes: Uint8Array, view: DataView): void => {
  writeAscii(bytes, SYMBOL_TABLE_OFFSET, ".file", COFF_SHORT_NAME_BYTE_LENGTH);
  writeCoffField(view, SYMBOL_TABLE_OFFSET, COFF_SYMBOL_FIELDS.SectionNumber, -2);
  writeCoffField(view, SYMBOL_TABLE_OFFSET, COFF_SYMBOL_FIELDS.StorageClass, COFF_STORAGE_CLASS.FILE);
  writeCoffField(view, SYMBOL_TABLE_OFFSET, COFF_SYMBOL_FIELDS.NumberOfAuxSymbols, 1);
  writeAscii(bytes, SYMBOL_TABLE_OFFSET + COFF_SYMBOL_RECORD_BYTE_LENGTH, "main.c", COFF_SYMBOL_RECORD_BYTE_LENGTH);
  const targetSymbolOffset = SYMBOL_TABLE_OFFSET + COFF_SYMBOL_RECORD_BYTE_LENGTH * 2;
  writeAscii(bytes, targetSymbolOffset, "target", COFF_SHORT_NAME_BYTE_LENGTH);
  writeCoffField(view, targetSymbolOffset, COFF_SYMBOL_FIELDS.SectionNumber, 1);
  writeCoffField(view, targetSymbolOffset, COFF_SYMBOL_FIELDS.StorageClass, COFF_STORAGE_CLASS.EXTERNAL);
};

export const createCoffObjectBytes = (): Uint8Array => {
  const bytes = new Uint8Array(STRING_TABLE_OFFSET + COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH).fill(0);
  const view = new DataView(bytes.buffer);
  writeCoffHeader(view);
  writeTextSectionHeader(bytes, view);
  bytes.set([0x90, 0x90, 0x90, 0xc3], SECTION_RAW_OFFSET);
  writeRelocation(view);
  writeSymbols(bytes, view);
  view.setUint32(STRING_TABLE_OFFSET, COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH, true);
  return bytes;
};

export const createCoffObjectFile = (): MockFile =>
  new MockFile(createCoffObjectBytes(), "sample.obj", "application/octet-stream");
