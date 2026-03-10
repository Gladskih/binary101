"use strict";

import type { MachOFileHeader } from "../../analyzers/macho/types.js";

// mach-o/loader.h: MH_CIGAM == 0xcefaedfe.
const LITTLE_ENDIAN_32_MAGIC = 0xcefaedfe;
// mach-o/loader.h: MH_CIGAM_64 == 0xcffaedfe.
const LITTLE_ENDIAN_64_MAGIC = 0xcffaedfe;
// mach-o/loader.h: MH_MAGIC_64 == 0xfeedfacf.
const BIG_ENDIAN_64_MAGIC = 0xfeedfacf;

const createSymtabHeader = (
  magic: number,
  filetype: number,
  flags: number
): MachOFileHeader => {
  const is64 = magic === LITTLE_ENDIAN_64_MAGIC || magic === BIG_ENDIAN_64_MAGIC;
  return {
    magic,
    is64,
    littleEndian: magic === LITTLE_ENDIAN_32_MAGIC || magic === LITTLE_ENDIAN_64_MAGIC,
    cputype: 0,
    cpusubtype: 0,
    filetype,
    ncmds: 0,
    sizeofcmds: 0,
    flags,
    reserved: is64 ? 0 : null
  };
};

export {
  BIG_ENDIAN_64_MAGIC,
  LITTLE_ENDIAN_32_MAGIC,
  LITTLE_ENDIAN_64_MAGIC,
  createSymtabHeader
};
