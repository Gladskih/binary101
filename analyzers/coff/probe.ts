"use strict";

import {
  COFF_FILE_CHARACTERISTICS,
  COFF_FILE_HEADER_BYTE_LENGTH,
  COFF_FILE_HEADER_FIELDS,
  COFF_PRINTABLE_SECTION_NAME_MAX_BYTE,
  COFF_PRINTABLE_SECTION_NAME_MIN_BYTE,
  COFF_SECTION_HEADER_BYTE_LENGTH,
  COFF_SHORT_NAME_BYTE_LENGTH,
  readCoffField
} from "./layout.js";
import { formatCoffMachine, isKnownCoffMachine } from "./machine.js";

type CoffObjectProbe = {
  machine: number;
};

const hasPrintableSectionName = (dv: DataView, sectionOffset: number): boolean => {
  const values = Array.from(
    { length: COFF_SHORT_NAME_BYTE_LENGTH },
    (_, index) => dv.getUint8(sectionOffset + index)
  );
  return values.some(value => value !== 0) &&
    values.every(value =>
      value === 0 ||
      (
        value >= COFF_PRINTABLE_SECTION_NAME_MIN_BYTE &&
        value <= COFF_PRINTABLE_SECTION_NAME_MAX_BYTE
      )
    );
};

const hasPlausibleSectionTable = (dv: DataView, numberOfSections: number): boolean => {
  const availableSections = Math.min(
    numberOfSections,
    Math.floor(
      Math.max(0, dv.byteLength - COFF_FILE_HEADER_BYTE_LENGTH) /
      COFF_SECTION_HEADER_BYTE_LENGTH
    )
  );
  if (availableSections === 0) return false;
  return Array.from({ length: availableSections }, (_, index) =>
    COFF_FILE_HEADER_BYTE_LENGTH + index * COFF_SECTION_HEADER_BYTE_LENGTH
  ).some(sectionOffset => hasPrintableSectionName(dv, sectionOffset));
};

const hasPlausibleSymbolTable = (
  fileSize: number,
  pointerToSymbolTable: number,
  numberOfSymbols: number,
  sectionTableEnd: number
): boolean => {
  if (pointerToSymbolTable === 0 && numberOfSymbols === 0) return true;
  if (pointerToSymbolTable < sectionTableEnd || numberOfSymbols === 0) return false;
  return pointerToSymbolTable <= fileSize;
};

export const probeCoffObject = (dv: DataView, fileSize: number): CoffObjectProbe | null => {
  // Stryker disable next-line EqualityOperator: header-only COFF is rejected by section-table probe.
  if (dv.byteLength < COFF_FILE_HEADER_BYTE_LENGTH) return null;
  const machine = readCoffField(dv, 0, COFF_FILE_HEADER_FIELDS.Machine);
  const numberOfSections = readCoffField(dv, 0, COFF_FILE_HEADER_FIELDS.NumberOfSections);
  const pointerToSymbolTable = readCoffField(dv, 0, COFF_FILE_HEADER_FIELDS.PointerToSymbolTable);
  const numberOfSymbols = readCoffField(dv, 0, COFF_FILE_HEADER_FIELDS.NumberOfSymbols);
  const sizeOfOptionalHeader = readCoffField(dv, 0, COFF_FILE_HEADER_FIELDS.SizeOfOptionalHeader);
  const characteristics = readCoffField(dv, 0, COFF_FILE_HEADER_FIELDS.Characteristics);
  if (!isKnownCoffMachine(machine) || sizeOfOptionalHeader !== 0) return null;
  if (
    (characteristics & (
      COFF_FILE_CHARACTERISTICS.EXECUTABLE_IMAGE |
      COFF_FILE_CHARACTERISTICS.DLL
    )) !== 0
  ) {
    return null;
  }
  const sectionTableEnd = COFF_FILE_HEADER_BYTE_LENGTH + numberOfSections * COFF_SECTION_HEADER_BYTE_LENGTH;
  if (sectionTableEnd > fileSize || !hasPlausibleSectionTable(dv, numberOfSections)) return null;
  return hasPlausibleSymbolTable(fileSize, pointerToSymbolTable, numberOfSymbols, sectionTableEnd)
    ? { machine }
    : null;
};

export const buildCoffObjectLabel = (probe: CoffObjectProbe): string =>
  `COFF object file for ${formatCoffMachine(probe.machine)}`;
