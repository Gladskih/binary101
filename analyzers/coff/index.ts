"use strict";

import { createFileRangeReader } from "../file-range-reader.js";
import { parseCoffFileHeaderAt } from "./file-header.js";
import { parseCoffSectionHeaders } from "./section-headers.js";
import { addCoffSectionEntropy } from "./raw-data.js";
import { parseCoffRelocations } from "./relocations.js";
import { parseCoffDebugInfoFromFileHeader } from "./debug.js";
import { isKnownCoffMachine } from "./machine.js";
import { COFF_FILE_CHARACTERISTICS, COFF_FILE_HEADER_BYTE_LENGTH } from "./layout.js";
import type { CoffObjectParseResult } from "./types.js";

const appendWarning = (warnings: string[], message: string): void => {
  if (!warnings.includes(message)) warnings.push(message);
};

const hasImageOnlyCharacteristics = (characteristics: number): boolean =>
  (characteristics & (
    COFF_FILE_CHARACTERISTICS.EXECUTABLE_IMAGE |
    COFF_FILE_CHARACTERISTICS.DLL
  )) !== 0;

export async function parseCoffObject(file: File): Promise<CoffObjectParseResult | null> {
  const reader = createFileRangeReader(file, 0, file.size);
  const header = await parseCoffFileHeaderAt(reader, 0);
  if (
    !header ||
    header.SizeOfOptionalHeader !== 0 ||
    header.NumberOfSections === 0 ||
    !isKnownCoffMachine(header.Machine) ||
    hasImageOnlyCharacteristics(header.Characteristics)
  ) {
    return null;
  }

  const sectionResult = await parseCoffSectionHeaders(
    reader,
    COFF_FILE_HEADER_BYTE_LENGTH,
    0,
    header.NumberOfSections,
    header.PointerToSymbolTable,
    header.NumberOfSymbols
  );
  await addCoffSectionEntropy(reader, sectionResult.sections);
  const warnings = [...(sectionResult.warnings ?? [])];
  const relocations = await parseCoffRelocations(
    reader,
    sectionResult.sections,
    message => appendWarning(warnings, message)
  );
  const coffDebug = await parseCoffDebugInfoFromFileHeader(
    reader,
    header.PointerToSymbolTable,
    header.NumberOfSymbols,
    sectionResult.sections,
    message => appendWarning(warnings, message)
  );
  return {
    signature: "COFF",
    header,
    sections: sectionResult.sections,
    ...(relocations.length ? { relocations } : {}),
    ...(sectionResult.coffStringTableSize != null
      ? { coffStringTableSize: sectionResult.coffStringTableSize }
      : {}),
    ...(coffDebug ? { coffDebug } : {}),
    ...(warnings.length ? { warnings } : {})
  };
}
