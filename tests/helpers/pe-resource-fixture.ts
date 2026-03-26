"use strict";

import { buildResourceTree } from "../../analyzers/pe/resources-core.js";
import { MockFile } from "./mock-file.js";
import { expectDefined } from "./expect-defined.js";

/** Size of one `IMAGE_RESOURCE_DIRECTORY` header in bytes. */
export const IMAGE_RESOURCE_DIRECTORY_SIZE = 16; // IMAGE_RESOURCE_DIRECTORY
/** Size of one `IMAGE_RESOURCE_DIRECTORY_ENTRY` record in bytes. */
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

/**
 * Encodes a resource-directory Name field that points to a length-prefixed UTF-16 string.
 */
export const resourceNameString = (relativeOffset: number): number =>
  RESOURCE_DIRECTORY_FLAG_MASK | relativeOffset;

export const resourceSubdirectory = (relativeOffset: number): number =>
  RESOURCE_DIRECTORY_FLAG_MASK | relativeOffset;

/**
 * Writable `.rsrc` fixture buffer plus focused operations for emitting PE resource records.
 */
export interface PeResourceDirectoryFixture {
  /** Backing bytes for the synthetic resource section. */
  bytes: Uint8Array;
  /**
   * Writes the trailing count fields of one `IMAGE_RESOURCE_DIRECTORY`.
   * The caller chooses the directory offset within `bytes`.
   */
  writeDirectory: (offset: number, namedCount: number, idCount: number) => void;
  /**
   * Writes one `IMAGE_RESOURCE_DIRECTORY_ENTRY` at the given offset.
   * `nameField` and `targetField` are the raw 32-bit fields from the PE structure.
   */
  writeDirectoryEntry: (offset: number, nameField: number, targetField: number) => void;
  /**
   * Writes a length-prefixed UTF-16 resource name string.
   * `declaredLength` can differ from `text.length` to model malformed fixtures.
   */
  writeUtf16Label: (offset: number, text: string, declaredLength?: number) => void;
  /**
   * Writes one `IMAGE_RESOURCE_DATA_ENTRY`.
   * `reserved` defaults to zero because the PE format expects this field to be zero.
   */
  writeDataEntry: (
    offset: number,
    dataRva: number,
    size: number,
    codePage: number,
    reserved?: number
  ) => void;
}

/** Sparse RVA-to-file mapping segment used by PE resource tests. */
export interface SparseResourceSegment {
  fileOffset: number;
  rvaStart: number;
  length: number;
}

/**
 * Builds a zero-filled `.rsrc` fixture buffer and returns writer functions for PE resource
 * directory structures used in tests.
 */
export const createResourceDirectoryFixture = (fileSize: number): PeResourceDirectoryFixture => {
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

/**
 * Builds an `rvaToOff` mapper from sparse virtual/file segments for resource-parser tests.
 */
export const createSparseResourceRvaToOffset = (
  segments: SparseResourceSegment[]
): ((rva: number) => number | null) => (rva: number): number | null => {
  for (const segment of segments) {
    if (rva >= segment.rvaStart && rva < segment.rvaStart + segment.length) {
      return segment.fileOffset + (rva - segment.rvaStart);
    }
  }
  return null;
};

/**
 * Parses a resource tree from raw fixture bytes using a synthetic `RESOURCE` data-directory entry.
 * Tests can override the file name, RVA mapper, and coverage collector without building a full PE.
 */
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
