"use strict";

import { open } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";

interface PeCoffSymbolHeader {
  pointerToSymbolTable: number;
  symbolCount: number;
}

interface PeCoffSymbolReadResult {
  header: PeCoffSymbolHeader | null;
  warnings: string[];
}

export interface PeCoffSymbolValidationResult {
  error: string | null;
  header: PeCoffSymbolHeader | null;
  warnings: string[];
}

// PE offsets below follow IMAGE_DOS_HEADER.e_lfanew and IMAGE_FILE_HEADER fields:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
const dosHeaderSize = 0x40;
const eLfanewOffset = 0x3c;
const peSignatureSize = 4;
const coffHeaderSize = 20;
const peSignature = 0x00004550;
const pointerToSymbolTableOffset = 8;
const symbolCountOffset = 12;

const readExact = async (
  file: FileHandle,
  length: number,
  position: number
): Promise<Buffer | null> => {
  const buffer = Buffer.alloc(length);
  const result = await file.read(buffer, 0, length, position);
  return result.bytesRead === length ? buffer : null;
};

const readPeCoffSymbolHeader = async (filePath: string): Promise<PeCoffSymbolReadResult> => {
  let file: FileHandle;
  try {
    file = await open(filePath, "r");
  } catch (error) {
    return { header: null, warnings: [`Could not open PE file: ${String(error)}`] };
  }
  try {
    const dos = await readExact(file, dosHeaderSize, 0);
    if (!dos) return { header: null, warnings: ["File is too small for an MZ header."] };
    if (dos.toString("ascii", 0, 2) !== "MZ") {
      return { header: null, warnings: ["File does not start with an MZ signature."] };
    }
    const peOffset = dos.readUInt32LE(eLfanewOffset);
    const coff = await readExact(file, peSignatureSize + coffHeaderSize, peOffset);
    if (!coff) return { header: null, warnings: ["File is too small for a PE/COFF header."] };
    if (coff.readUInt32LE(0) !== peSignature) {
      return { header: null, warnings: ["e_lfanew does not point to a PE signature."] };
    }
    return {
      header: {
        pointerToSymbolTable: coff.readUInt32LE(peSignatureSize + pointerToSymbolTableOffset),
        symbolCount: coff.readUInt32LE(peSignatureSize + symbolCountOffset)
      },
      warnings: []
    };
  } finally {
    await file.close();
  }
};

export const validateNoPeCoffSymbolRecords = async (
  filePath: string
): Promise<PeCoffSymbolValidationResult> => {
  const read = await readPeCoffSymbolHeader(filePath);
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
