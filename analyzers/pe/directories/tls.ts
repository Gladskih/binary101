"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import {
  formatTlsCharacteristicsReservedBits,
  isKnownTlsCharacteristicsAlignment,
  tlsCharacteristicsReservedBits
} from "../tls-characteristics.js";
import type { PeDataDirectory, PeSection, PeTlsDirectory, RvaToOffset } from "../types.js";
import { isReadableMappedTlsVa, isTlsImageVa } from "./tls-addresses.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import { readTlsCallbacks } from "./tls-callbacks.js";

const TLS_INDEX_STORAGE_SIZE = Uint32Array.BYTES_PER_ELEMENT;

const createTlsWarningResult = (warnings: string[]): PeTlsDirectory => ({
  StartAddressOfRawData: 0n,
  EndAddressOfRawData: 0n,
  AddressOfIndex: 0n,
  AddressOfCallBacks: 0n,
  SizeOfZeroFill: 0,
  Characteristics: 0,
  CallbackCount: 0,
  CallbackRvas: [],
  warnings,
  parsed: false
});

const addTlsRawDataWarnings = (
  startAddressOfRawData: bigint,
  endAddressOfRawData: bigint,
  imageBase: bigint,
  rvaToOff: RvaToOffset,
  fileSize: number,
  warnings: string[]
): void => {
  if (startAddressOfRawData === 0n && endAddressOfRawData === 0n) return;
  if (startAddressOfRawData === 0n || endAddressOfRawData === 0n || endAddressOfRawData < startAddressOfRawData) {
    warnings.push("TLS raw data VA range is invalid.");
    return;
  }
  const lastRawDataByteVa = endAddressOfRawData > startAddressOfRawData
    ? endAddressOfRawData - 1n
    : endAddressOfRawData;
  if (
    !isReadableMappedTlsVa(startAddressOfRawData, 1, imageBase, rvaToOff, fileSize) ||
    !isReadableMappedTlsVa(lastRawDataByteVa, 1, imageBase, rvaToOff, fileSize)
  ) {
    warnings.push("TLS raw data VA range does not map to file data.");
  }
};

const addTlsFieldWarnings = (
  startAddressOfRawData: bigint,
  endAddressOfRawData: bigint,
  characteristics: number,
  imageBase: bigint,
  rvaToOff: RvaToOffset,
  fileSize: number,
  warnings: string[]
): void => {
  if (tlsCharacteristicsReservedBits(characteristics) !== 0) {
    warnings.push(
      `TLS Characteristics has reserved bits set: ${formatTlsCharacteristicsReservedBits(characteristics)}.`
    );
  }
  if (!isKnownTlsCharacteristicsAlignment(characteristics)) {
    warnings.push("TLS Characteristics uses an unknown alignment value.");
  }
  addTlsRawDataWarnings(startAddressOfRawData, endAddressOfRawData, imageBase, rvaToOff, fileSize, warnings);
};

const addTlsIndexWarning = (
  addressOfIndex: bigint,
  imageBase: bigint,
  sections: PeSection[],
  warnings: string[]
): void => {
  // Microsoft PE format, "The TLS Directory": AddressOfIndex is the VA of an
  // ordinary data location where the loader writes the module TLS index.
  // That slot may be in virtual zero-fill data, so file-backed readability is
  // not required.
  if (!isTlsImageVa(addressOfIndex, TLS_INDEX_STORAGE_SIZE, imageBase, sections)) {
    warnings.push(`TLS AddressOfIndex pointer 0x${addressOfIndex.toString(16)} is not a valid image VA.`);
  }
};

const readTlsHeader = async (
  reader: FileRangeReader,
  dir: PeDataDirectory,
  rvaToOff: RvaToOffset,
  pointerSize: 4 | 8,
  warnings: string[]
): Promise<DataView | null> => {
  // Microsoft PE format, The TLS Directory: four VAs followed by two DWORDs.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-directory
  const headerSize = pointerSize * 4 + 8;
  if (!dir.rva) {
    warnings.push("TLS directory has a non-zero size but RVA is 0.");
    return null;
  }
  if (dir.size < headerSize) {
    warnings.push(`TLS directory is smaller than the ${pointerSize * 8}-bit TLS header size (0x${headerSize.toString(16)} bytes).`);
    return null;
  }
  if (rvaToOff(dir.rva) == null) {
    warnings.push("TLS directory RVA could not be mapped to a file offset.");
    return null;
  }
  const view = await readMappedRvaPrefix(reader, dir.rva, headerSize, rvaToOff);
  if (view.byteLength !== headerSize) {
    warnings.push(`TLS directory is truncated or unmapped before the full ${pointerSize * 8}-bit header could be read.`);
    return null;
  }
  return view;
};

const readTlsFields = (view: DataView, pointerSize: 4 | 8) => {
  const readPointer = (index: number): bigint => pointerSize === 4
    ? BigInt(view.getUint32(index * pointerSize, true))
    : view.getBigUint64(index * pointerSize, true);
  return {
    StartAddressOfRawData: readPointer(0),
    EndAddressOfRawData: readPointer(1),
    AddressOfIndex: readPointer(2),
    AddressOfCallBacks: readPointer(3),
    SizeOfZeroFill: view.getUint32(pointerSize * 4, true),
    Characteristics: view.getUint32(pointerSize * 4 + 4, true)
  };
};

const parseTlsDirectory = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  sections: PeSection[],
  pointerSize: 4 | 8
): Promise<PeTlsDirectory | null> => {
  const dir = dataDirs.find(entry => entry.name === "TLS");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  const warnings: string[] = [];
  const view = await readTlsHeader(reader, dir, rvaToOff, pointerSize, warnings);
  if (!view) return createTlsWarningResult(warnings);
  const fields = readTlsFields(view, pointerSize);
  addTlsFieldWarnings(
    fields.StartAddressOfRawData, fields.EndAddressOfRawData, fields.Characteristics,
    imageBase, rvaToOff, reader.size, warnings
  );
  addTlsIndexWarning(fields.AddressOfIndex, imageBase, sections, warnings);
  const callbacks = await readTlsCallbacks(
    reader, rvaToOff, fields.AddressOfCallBacks, imageBase, pointerSize, warnings
  );
  return {
    ...fields,
    CallbackCount: callbacks.rvas.length,
    CallbackRvas: callbacks.rvas,
    callbackTableStatus: callbacks.status,
    ...(warnings.length ? { warnings } : {}),
    parsed: true
  };
};

export const parseTlsDirectory32 = (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  sections: PeSection[] = []
): Promise<PeTlsDirectory | null> =>
  parseTlsDirectory(reader, dataDirs, rvaToOff, imageBase, sections, 4);

export const parseTlsDirectory64 = (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  sections: PeSection[] = []
): Promise<PeTlsDirectory | null> =>
  parseTlsDirectory(reader, dataDirs, rvaToOff, imageBase, sections, 8);
