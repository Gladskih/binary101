"use strict";

import { FAT_MAGIC_64 } from "../../analyzers/macho/commands.js";
import { MockFile } from "../helpers/mock-file.js";
import type { ThinMachOFixture, ThinMachOFixtureLayout } from "./macho-thin-types.js";
import { CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_X86_64, createThinMachOFixture } from "./macho-thin-sample.js";
import type { UniversalMachOFixture } from "./macho-universal-sample.js";
import { createUniversalMachOFixture } from "./macho-universal-sample.js";

const cloneBytes = (bytes: Uint8Array): Uint8Array => new Uint8Array(bytes);

const createMockMachOFile = (bytes: Uint8Array, name: string): MockFile =>
  new MockFile(bytes, name, "application/octet-stream");

const createDefaultThinMachOFixture = (): ThinMachOFixture =>
  createThinMachOFixture(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x10, "com.example.binary101");

export const createThinMachOBytes = (): Uint8Array =>
  cloneBytes(createDefaultThinMachOFixture().bytes);

export const createThinMachOLayout = (): ThinMachOFixtureLayout =>
  createDefaultThinMachOFixture().layout;

export const createThinMachOFixtureData = (): ThinMachOFixture =>
  createDefaultThinMachOFixture();

export const createMachOFile = (): MockFile =>
  createMockMachOFile(createThinMachOBytes(), "sample-macho");

export const createMachOUniversalBytes = (): Uint8Array =>
  cloneBytes(createUniversalMachOFixture().bytes);

export const createMachOUniversalLayout = (): UniversalMachOFixture =>
  createUniversalMachOFixture();

export const createMachOUniversalFile = (): MockFile =>
  createMockMachOFile(createMachOUniversalBytes(), "sample-universal");

export const createTruncatedFatMachOBytes = (magic = FAT_MAGIC_64): Uint8Array => {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, magic, false);
  return bytes;
};

export const wrapMachOBytes = (bytes: Uint8Array, name = "sample-macho"): MockFile =>
  createMockMachOFile(bytes, name);
