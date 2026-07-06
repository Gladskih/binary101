"use strict";

import { open } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { COFF_FILE_HEADER_BYTE_LENGTH, COFF_FILE_HEADER_FIELDS } from "../../analyzers/coff/layout.js";

interface PeLegacyCoffSymbolHeader {
  pointerToSymbolTable: number;
  symbolCount: number;
}

interface PeLegacyCoffSymbolReadResult {
  header: PeLegacyCoffSymbolHeader | null;
  warnings: string[];
}

export interface PeLegacyCoffSymbolValidationResult {
  error: string | null;
  header: PeLegacyCoffSymbolHeader | null;
  warnings: string[];
}

// PE offsets below follow IMAGE_DOS_HEADER.e_lfanew and IMAGE_FILE_HEADER fields:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
const DOS_HEADER_BYTE_LENGTH = 0x40;
const DOS_E_LFANEW_OFFSET = 0x3c;
const PE_SIGNATURE_BYTE_LENGTH = Uint32Array.BYTES_PER_ELEMENT;
const PE_SIGNATURE = 0x00004550;

const readExact = async (
  file: FileHandle,
  length: number,
  position: number
): Promise<Buffer | null> => {
  const buffer = Buffer.alloc(length);
  const result = await file.read(buffer, 0, length, position);
  return result.bytesRead === length ? buffer : null;
};

const readPeLegacyCoffSymbolHeader = async (
  filePath: string
): Promise<PeLegacyCoffSymbolReadResult> => {
  let file: FileHandle;
  try {
    file = await open(filePath, "r");
  } catch (error) {
    return { header: null, warnings: [`Could not open PE file: ${String(error)}`] };
  }
  try {
    const dos = await readExact(file, DOS_HEADER_BYTE_LENGTH, 0);
    if (!dos) return { header: null, warnings: ["File is too small for an MZ header."] };
    if (dos.toString("ascii", 0, 2) !== "MZ") {
      return { header: null, warnings: ["File does not start with an MZ signature."] };
    }
    const peOffset = dos.readUInt32LE(DOS_E_LFANEW_OFFSET);
    const coff = await readExact(file, PE_SIGNATURE_BYTE_LENGTH + COFF_FILE_HEADER_BYTE_LENGTH, peOffset);
    if (!coff) return { header: null, warnings: ["File is too small for a PE/COFF header."] };
    if (coff.readUInt32LE(0) !== PE_SIGNATURE) {
      return { header: null, warnings: ["e_lfanew does not point to a PE signature."] };
    }
    return {
      header: {
        pointerToSymbolTable: coff.readUInt32LE(
          PE_SIGNATURE_BYTE_LENGTH + COFF_FILE_HEADER_FIELDS.PointerToSymbolTable.offset
        ),
        symbolCount: coff.readUInt32LE(
          PE_SIGNATURE_BYTE_LENGTH + COFF_FILE_HEADER_FIELDS.NumberOfSymbols.offset
        )
      },
      warnings: []
    };
  } finally {
    await file.close();
  }
};

export const validateNoPeLegacyCoffSymbolRecords = async (
  filePath: string
): Promise<PeLegacyCoffSymbolValidationResult> => {
  const read = await readPeLegacyCoffSymbolHeader(filePath);
  if (!read.header) {
    return { error: read.warnings.join(" "), header: null, warnings: read.warnings };
  }
  if (read.header.symbolCount !== 0) {
    return {
      error: "PE image has a COFF symbol table; primary PE outputs must keep COFF symbols out of the executable.",
      header: read.header,
      warnings: []
    };
  }
  if (read.header.pointerToSymbolTable !== 0) {
    return {
      error: null,
      header: read.header,
      warnings: [
        "PE header has a nonzero PointerToSymbolTable but NumberOfSymbols is zero; no COFF symbol records are present."
      ]
    };
  }
  return { error: null, header: read.header, warnings: [] };
};
