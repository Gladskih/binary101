"use strict";

import {
  COFF_FILE_CHARACTERISTICS,
  COFF_FILE_HEADER_BYTE_LENGTH,
  COFF_FILE_HEADER_FIELDS,
  type CoffNumericField
} from "../../analyzers/coff/layout.js";
import { IMAGE_FILE_MACHINE_I386 } from "../../analyzers/coff/machine.js";

const DOS_SIGNATURE = 0x5a4d;
const DOS_E_LFANEW_OFFSET = 0x3c;
const PE_SIGNATURE = 0x00004550;
const PE_SIGNATURE_BYTE_LENGTH = Uint32Array.BYTES_PER_ELEMENT;
const FIXTURE_PE_SIGNATURE_OFFSET = 64;
const FIXTURE_PE32_OPTIONAL_HEADER_SIZE = 224;

export const MINIMAL_PE32_IMAGE_BASE = 0x00400000n;
export const MINIMAL_PE32_OPTIONAL_HEADER_MAGIC = 0x10b;

const writeCoffHeaderField = (
  view: DataView,
  coffHeaderOffset: number,
  field: CoffNumericField,
  value: number
): void => {
  const offset = coffHeaderOffset + field.offset;
  if (field.width === "u8") view.setUint8(offset, value);
  else if (field.width === "u16") view.setUint16(offset, value, true);
  else if (field.width === "i16") view.setInt16(offset, value, true);
  else view.setUint32(offset, value, true);
};

const writeMinimalPePrefix = (
  view: DataView,
  peSignatureOffset: number,
  optionalHeaderSize: number
): number => {
  view.setUint16(0, DOS_SIGNATURE, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, peSignatureOffset, true);
  view.setUint32(peSignatureOffset, PE_SIGNATURE, true);

  const coffHeaderOffset = peSignatureOffset + PE_SIGNATURE_BYTE_LENGTH;
  writeCoffHeaderField(view, coffHeaderOffset, COFF_FILE_HEADER_FIELDS.Machine, IMAGE_FILE_MACHINE_I386);
  writeCoffHeaderField(view, coffHeaderOffset, COFF_FILE_HEADER_FIELDS.NumberOfSections, 0);
  writeCoffHeaderField(view, coffHeaderOffset, COFF_FILE_HEADER_FIELDS.TimeDateStamp, 0);
  writeCoffHeaderField(view, coffHeaderOffset, COFF_FILE_HEADER_FIELDS.PointerToSymbolTable, 0);
  writeCoffHeaderField(view, coffHeaderOffset, COFF_FILE_HEADER_FIELDS.NumberOfSymbols, 0);
  writeCoffHeaderField(view, coffHeaderOffset, COFF_FILE_HEADER_FIELDS.SizeOfOptionalHeader, optionalHeaderSize);
  writeCoffHeaderField(
    view,
    coffHeaderOffset,
    COFF_FILE_HEADER_FIELDS.Characteristics,
    COFF_FILE_CHARACTERISTICS.EXECUTABLE_IMAGE
  );
  return coffHeaderOffset + COFF_FILE_HEADER_BYTE_LENGTH;
};

export const createTinyPEHeader = (): Uint8Array => {
  const totalHeaderSize = FIXTURE_PE_SIGNATURE_OFFSET +
    PE_SIGNATURE_BYTE_LENGTH +
    COFF_FILE_HEADER_BYTE_LENGTH +
    FIXTURE_PE32_OPTIONAL_HEADER_SIZE;
  const buffer = new ArrayBuffer(totalHeaderSize);
  const view = new DataView(buffer);
  const optionalHeaderOffset = writeMinimalPePrefix(
    view,
    FIXTURE_PE_SIGNATURE_OFFSET,
    FIXTURE_PE32_OPTIONAL_HEADER_SIZE
  );

  view.setUint16(optionalHeaderOffset, MINIMAL_PE32_OPTIONAL_HEADER_MAGIC, true);
  view.setUint32(optionalHeaderOffset + 28, Number(MINIMAL_PE32_IMAGE_BASE), true);
  view.setUint32(optionalHeaderOffset + 56, totalHeaderSize, true);

  return new Uint8Array(buffer);
};

export const createHeadersOnlyPeWithAlignedImageSize = (): Uint8Array => {
  const fileAlignment = 0x200;
  const sectionAlignment = 0x1000;
  const buffer = new ArrayBuffer(fileAlignment);
  const view = new DataView(buffer);
  const optionalHeaderOffset = writeMinimalPePrefix(
    view,
    FIXTURE_PE_SIGNATURE_OFFSET,
    FIXTURE_PE32_OPTIONAL_HEADER_SIZE
  );

  view.setUint16(optionalHeaderOffset, MINIMAL_PE32_OPTIONAL_HEADER_MAGIC, true);
  view.setUint32(optionalHeaderOffset + 28, Number(MINIMAL_PE32_IMAGE_BASE), true);
  view.setUint32(optionalHeaderOffset + 32, sectionAlignment, true);
  view.setUint32(optionalHeaderOffset + 36, fileAlignment, true);
  view.setUint32(optionalHeaderOffset + 56, sectionAlignment, true);
  view.setUint32(optionalHeaderOffset + 60, fileAlignment, true);

  return new Uint8Array(buffer);
};
