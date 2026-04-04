"use strict";

import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { PeSection } from "../../analyzers/pe/types.js";
import {
  coffStringTablePeSectionName,
  inlinePeSectionName
} from "../../analyzers/pe/section-name.js";

export const createBasePe = (): PeParseResult =>
  ({
    dos: {
      e_magic: "MZ",
      e_cblp: 0,
      e_cp: 0,
      e_crlc: 0,
      e_cparhdr: 0,
      e_minalloc: 0,
      e_maxalloc: 0,
      e_ss: 0,
      e_sp: 0,
      e_csum: 0,
      e_ip: 0,
      e_cs: 0,
      e_lfarlc: 0,
      e_oemid: 0,
      e_oeminfo: 0,
      e_lfanew: 0x80,
      stub: { kind: "stub", note: "" }
    },
    coff: {
      Machine: 0x14c,
      NumberOfSections: 0,
      TimeDateStamp: 0,
      PointerToSymbolTable: 0,
      NumberOfSymbols: 0,
      SizeOfOptionalHeader: 0,
      Characteristics: 0
    },
    opt: {
      Magic: 0x10b,
      LinkerMajor: 0,
      LinkerMinor: 0,
      SizeOfCode: 0,
      SizeOfInitializedData: 0,
      SizeOfUninitializedData: 0,
      AddressOfEntryPoint: 0,
      BaseOfCode: 0x1000,
      BaseOfData: 0x2000,
      ImageBase: 0x400000n,
      SectionAlignment: 0x1000,
      FileAlignment: 0x200,
      OSVersionMajor: 0,
      OSVersionMinor: 0,
      ImageVersionMajor: 0,
      ImageVersionMinor: 0,
      SubsystemVersionMajor: 0,
      SubsystemVersionMinor: 0,
      Subsystem: 2,
      DllCharacteristics: 0,
      Win32VersionValue: 0,
      SizeOfImage: 0,
      SizeOfHeaders: 0,
      CheckSum: 0,
      SizeOfStackReserve: 0n,
      SizeOfStackCommit: 0n,
      SizeOfHeapReserve: 0n,
      SizeOfHeapCommit: 0n,
      LoaderFlags: 0,
      NumberOfRvaAndSizes: 0
    },
    dirs: [],
    sections: [],
    entrySection: null,
    rvaToOff: (() => null) as unknown,
    debug: null,
    imports: { entries: [] },
    loadcfg: null,
    exports: null as unknown,
    tls: null,
    reloc: null as unknown,
    exception: null as unknown,
    boundImports: null as unknown,
    delayImports: null as unknown,
    clr: null,
    security: null,
    iat: null,
    importLinking: null,
    resources: null,
    overlaySize: 0,
    imageEnd: 0,
    imageSizeMismatch: false,
    hasCert: false,
    signature: "PE"
  }) as unknown as PeParseResult;

export const createPeSection = (
  name: string,
  overrides: Partial<Omit<PeSection, "name">> & { coffStringTableOffset?: number } = {}
): PeSection => {
  const { coffStringTableOffset, ...sectionOverrides } = overrides;
  return {
    name:
      coffStringTableOffset != null
        ? coffStringTablePeSectionName(name, coffStringTableOffset)
        : inlinePeSectionName(name),
    virtualSize: 0x100,
    virtualAddress: 0x1000,
    sizeOfRawData: 0x200,
    pointerToRawData: 0x400,
    characteristics: 0x60000020,
    ...sectionOverrides
  };
};

export const createPeWithSections = (...sections: PeSection[]): PeParseResult => {
  const pe = createBasePe();
  pe.sections = sections;
  pe.coff.NumberOfSections = sections.length;
  return pe;
};
