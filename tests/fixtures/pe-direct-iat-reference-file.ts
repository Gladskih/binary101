"use strict";

import {
  Code,
  Encoder,
  Instruction,
  MemoryOperand,
  Register
} from "iced-x86";
import { MockFile } from "../helpers/mock-file.js";
import { createPePlusWithSection } from "./sample-files-pe.js";

// Microsoft PE format field sizes, offsets, and data-directory indices used to extend the
// existing PE32+ fixture with one IMAGE_IMPORT_DESCRIPTOR and two named imports.
const DOS_E_LFANEW_OFFSET = 0x3c;
const PE_SIGNATURE_SIZE = 4;
const COFF_HEADER_SIZE = 20;
const COFF_OPTIONAL_HEADER_SIZE_OFFSET = 16;
const PE32_PLUS_ENTRYPOINT_OFFSET = 16;
const PE32_PLUS_IMAGE_BASE_OFFSET = 24;
const PE32_PLUS_DATA_DIRECTORIES_OFFSET = 112;
const DATA_DIRECTORY_ENTRY_SIZE = 8;
const IMPORT_DIRECTORY_INDEX = 1;
const IAT_DIRECTORY_INDEX = 12;
const SECTION_VIRTUAL_ADDRESS_OFFSET = 12;
const SECTION_RAW_DATA_POINTER_OFFSET = 20;
const IMAGE_IMPORT_DESCRIPTOR_SIZE = 20;
const IMPORT_DESCRIPTOR_COUNT_WITH_TERMINATOR = 2;
const ASCII_NUL = 0;
const AMD64_BITNESS = 64;
const DATA_ALIGNMENT = BigUint64Array.BYTES_PER_ELEMENT;
const IMPORT_NAMES = ["Sleep", "ExitProcess"] as const;

const alignUp = (value: number, alignment: number): number =>
  Math.ceil(value / alignment) * alignment;

const asciiZ = (value: string): Uint8Array =>
  Uint8Array.from([...new TextEncoder().encode(value), ASCII_NUL]);

const encodeDirectIatCall = (
  instructionVa: bigint,
  iatVa: bigint
): Uint8Array => {
  const call = Instruction.createMem(
    Code.Call_rm64,
    MemoryOperand.createBaseDispl(Register.RIP, iatVa)
  );
  const nearReturn = Instruction.create(Code.Retnq);
  const encoder = new Encoder(AMD64_BITNESS);
  try {
    const callLength = encoder.encode(call, instructionVa);
    encoder.encode(nearReturn, instructionVa + BigInt(callLength));
    return encoder.takeBuffer();
  } finally {
    call.free();
    nearReturn.free();
    encoder.free();
  }
};

export const createPePlusDirectIatReferenceFile = (): MockFile => {
  const bytes = createPePlusWithSection();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const peOffset = view.getUint32(DOS_E_LFANEW_OFFSET, true);
  const coffOffset = peOffset + PE_SIGNATURE_SIZE;
  const optionalOffset = coffOffset + COFF_HEADER_SIZE;
  const optionalSize = view.getUint16(coffOffset + COFF_OPTIONAL_HEADER_SIZE_OFFSET, true);
  const sectionOffset = optionalOffset + optionalSize;
  const sectionRva = view.getUint32(sectionOffset + SECTION_VIRTUAL_ADDRESS_OFFSET, true);
  const sectionRawOffset = view.getUint32(sectionOffset + SECTION_RAW_DATA_POINTER_OFFSET, true);
  const entrypointRva = view.getUint32(optionalOffset + PE32_PLUS_ENTRYPOINT_OFFSET, true);
  const imageBase = view.getBigUint64(optionalOffset + PE32_PLUS_IMAGE_BASE_OFFSET, true);
  const directoriesOffset = optionalOffset + PE32_PLUS_DATA_DIRECTORIES_OFFSET;
  const iatDirectoryOffset = directoriesOffset + IAT_DIRECTORY_INDEX * DATA_DIRECTORY_ENTRY_SIZE;
  const iatRva = view.getUint32(iatDirectoryOffset, true);
  const rvaToOffset = (rva: number): number => sectionRawOffset + rva - sectionRva;
  const thunkCount = IMPORT_NAMES.length + 1;
  const thunkTableSize = thunkCount * BigUint64Array.BYTES_PER_ELEMENT;
  const lookupRva = iatRva + thunkTableSize;
  let cursorRva = lookupRva + thunkTableSize;
  const nameRvas = IMPORT_NAMES.map(name => {
    const rva = cursorRva;
    const encoded = asciiZ(name);
    const offset = rvaToOffset(rva);
    view.setUint16(offset, 0, true);
    bytes.set(encoded, offset + Uint16Array.BYTES_PER_ELEMENT);
    cursorRva += Uint16Array.BYTES_PER_ELEMENT + encoded.length;
    return rva;
  });
  cursorRva = alignUp(cursorRva, DATA_ALIGNMENT);
  const dllNameRva = cursorRva;
  const dllName = asciiZ("KERNEL32.dll");
  bytes.set(dllName, rvaToOffset(dllNameRva));
  cursorRva = alignUp(cursorRva + dllName.length, DATA_ALIGNMENT);
  const importDirectoryRva = cursorRva;
  const importDirectorySize =
    IMPORT_DESCRIPTOR_COUNT_WITH_TERMINATOR * IMAGE_IMPORT_DESCRIPTOR_SIZE;
  for (const [index, nameRva] of nameRvas.entries()) {
    view.setBigUint64(
      rvaToOffset(iatRva) + index * BigUint64Array.BYTES_PER_ELEMENT,
      BigInt(nameRva),
      true
    );
    view.setBigUint64(
      rvaToOffset(lookupRva) + index * BigUint64Array.BYTES_PER_ELEMENT,
      BigInt(nameRva),
      true
    );
  }
  const descriptorOffset = rvaToOffset(importDirectoryRva);
  view.setUint32(descriptorOffset, lookupRva, true);
  view.setUint32(descriptorOffset + 12, dllNameRva, true);
  view.setUint32(descriptorOffset + 16, iatRva, true);
  const importDirectoryOffset = directoriesOffset + IMPORT_DIRECTORY_INDEX * DATA_DIRECTORY_ENTRY_SIZE;
  view.setUint32(importDirectoryOffset, importDirectoryRva, true);
  view.setUint32(importDirectoryOffset + Uint32Array.BYTES_PER_ELEMENT, importDirectorySize, true);
  view.setUint32(iatDirectoryOffset + Uint32Array.BYTES_PER_ELEMENT, thunkTableSize, true);
  bytes.set(
    encodeDirectIatCall(imageBase + BigInt(entrypointRva), imageBase + BigInt(iatRva)),
    rvaToOffset(entrypointRva)
  );
  return new MockFile(
    bytes,
    "sample-x64-direct-iat.exe",
    "application/vnd.microsoft.portable-executable"
  );
};
