"use strict";

import type { PeOptionalHeader, PeRomOptionalFields } from "./types.js";
import {
  getOptionalHeaderKind,
  PE32_OPTIONAL_HEADER_MAGIC,
  PE32_PLUS_OPTIONAL_HEADER_MAGIC,
  ROM_OPTIONAL_HEADER_MAGIC
} from "./optional-header-kind.js";

export function createEmptyOptionalHeader(magic: number): PeOptionalHeader {
  const kind = getOptionalHeaderKind(magic);
  const common = {
    Magic: magic,
    LinkerMajor: 0,
    LinkerMinor: 0,
    SizeOfCode: 0,
    SizeOfInitializedData: 0,
    SizeOfUninitializedData: 0,
    AddressOfEntryPoint: 0,
    BaseOfCode: 0
  };
  const windows = {
    ImageBase: 0n,
    SectionAlignment: 0,
    FileAlignment: 0,
    OSVersionMajor: 0,
    OSVersionMinor: 0,
    ImageVersionMajor: 0,
    ImageVersionMinor: 0,
    SubsystemVersionMajor: 0,
    SubsystemVersionMinor: 0,
    Win32VersionValue: 0,
    SizeOfImage: 0,
    SizeOfHeaders: 0,
    CheckSum: 0,
    Subsystem: 0,
    DllCharacteristics: 0,
    SizeOfStackReserve: 0n,
    SizeOfStackCommit: 0n,
    SizeOfHeapReserve: 0n,
    SizeOfHeapCommit: 0n,
    LoaderFlags: 0,
    NumberOfRvaAndSizes: 0
  };
  const rom: PeRomOptionalFields = {
    BaseOfBss: 0,
    GprMask: 0,
    CprMask: [0, 0, 0, 0],
    GpValue: 0
  };
  switch (kind) {
    case "pe32":
      return { ...common, Magic: PE32_OPTIONAL_HEADER_MAGIC, ...windows, BaseOfData: 0 };
    case "pe32+":
      return { ...common, Magic: PE32_PLUS_OPTIONAL_HEADER_MAGIC, ...windows };
    case "rom":
      return { ...common, Magic: ROM_OPTIONAL_HEADER_MAGIC, BaseOfData: 0, rom };
    case "unknown":
      return common;
  }
}
