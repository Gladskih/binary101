"use strict";

import type { ElfProgramHeader, ElfSectionHeader, ElfTlsInfo } from "./types.js";

const PT_TLS = 7;
const SHF_TLS = 0x400;

const hasTlsFlag = (sec: ElfSectionHeader): boolean => {
  const flags = typeof sec.flags === "bigint" ? sec.flags : BigInt(sec.flags);
  return (flags & BigInt(SHF_TLS)) !== 0n;
};

export function parseElfTlsInfo(programHeaders: ElfProgramHeader[], sections: ElfSectionHeader[]): ElfTlsInfo | null {
  const segments = programHeaders
    .filter(ph => ph.type === PT_TLS && ph.memsz > 0n)
    .map(ph => ({
      index: ph.index,
      offset: ph.offset,
      vaddr: ph.vaddr,
      filesz: ph.filesz,
      memsz: ph.memsz,
      align: ph.align
    }));

  const tlsSections = sections
    .filter(sec => sec.size > 0n)
    .filter(sec => hasTlsFlag(sec) || sec.name === ".tdata" || sec.name === ".tbss")
    .map(sec => ({
      index: sec.index,
      name: sec.name || "",
      addr: sec.addr,
      offset: sec.offset,
      size: sec.size,
      flags: sec.flagNames
    }));

  if (!segments.length && !tlsSections.length) return null;
  return { segments, sections: tlsSections };
}

