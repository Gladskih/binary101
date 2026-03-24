"use strict";

import { buildResourceTree } from "../../analyzers/pe/resources-core.js";
import { MockFile } from "./mock-file.js";
import { expectDefined } from "./expect-defined.js";

export const IMAGE_RESOURCE_DIRECTORY_SIZE = 16; // IMAGE_RESOURCE_DIRECTORY
export const IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE = 8; // IMAGE_RESOURCE_DIRECTORY_ENTRY
export const IMAGE_RESOURCE_DATA_ENTRY_SIZE = 16; // IMAGE_RESOURCE_DATA_ENTRY

const RESOURCE_DIRECTORY_FLAG_MASK = 0x80000000;

const resourceDataDirectory = (rva: number, size: number) => [{ name: "RESOURCE", rva, size }];

const writeUtf16Text = (bytes: Uint8Array, offset: number, text: string): void => {
  for (let index = 0; index < text.length; index += 1) {
    const codeUnit = text.charCodeAt(index);
    bytes[offset + index * 2] = codeUnit & 0xff;
    bytes[offset + index * 2 + 1] = codeUnit >>> 8;
  }
};

export const resourceNameString = (relativeOffset: number): number =>
  RESOURCE_DIRECTORY_FLAG_MASK | relativeOffset;

export const resourceSubdirectory = (relativeOffset: number): number =>
  RESOURCE_DIRECTORY_FLAG_MASK | relativeOffset;

export const createResourceDirectoryFixture = (fileSize: number): {
  bytes: Uint8Array;
  writeDirectory: (offset: number, namedCount: number, idCount: number) => void;
  writeDirectoryEntry: (offset: number, nameField: number, targetField: number) => void;
  writeUtf16Label: (offset: number, text: string, declaredLength?: number) => void;
  writeDataEntry: (
    offset: number,
    dataRva: number,
    size: number,
    codePage: number,
    reserved?: number
  ) => void;
} => {
  const bytes = new Uint8Array(fileSize).fill(0);
  const view = new DataView(bytes.buffer);
  const writeDirectory = (offset: number, namedCount: number, idCount: number): void => {
    view.setUint16(offset + 12, namedCount, true);
    view.setUint16(offset + 14, idCount, true);
  };
  const writeDirectoryEntry = (offset: number, nameField: number, targetField: number): void => {
    view.setUint32(offset, nameField, true);
    view.setUint32(offset + Uint32Array.BYTES_PER_ELEMENT, targetField, true);
  };
  const writeUtf16Label = (offset: number, text: string, declaredLength = text.length): void => {
    view.setUint16(offset, declaredLength, true);
    writeUtf16Text(bytes, offset + Uint16Array.BYTES_PER_ELEMENT, text);
  };
  const writeDataEntry = (
    offset: number,
    dataRva: number,
    size: number,
    codePage: number,
    reserved = 0
  ): void => {
    view.setUint32(offset, dataRva, true);
    view.setUint32(offset + 4, size, true);
    view.setUint32(offset + 8, codePage, true);
    view.setUint32(offset + 12, reserved, true);
  };
  return { bytes, writeDirectory, writeDirectoryEntry, writeUtf16Label, writeDataEntry };
};

export const parseResourceTreeFixture = async (
  bytes: Uint8Array,
  resourceRva: number,
  resourceSize: number,
  rvaToOff: (value: number) => number | null,
  fileName = "resource.bin",
  addCoverageRegion: (label: string, start: number, size: number) => void = () => {}
) => expectDefined(
  await buildResourceTree(
    new MockFile(bytes, fileName),
    resourceDataDirectory(resourceRva, resourceSize),
    rvaToOff,
    addCoverageRegion
  )
);
