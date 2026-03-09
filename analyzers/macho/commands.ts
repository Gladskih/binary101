"use strict";

// Mach-O and universal-binary magic values, load-command IDs, nlist flags, and
// code-signing blob magics come from Apple's public headers:
// - mach-o/loader.h: https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/loader.h
// - mach-o/fat.h: https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/fat.h
// - mach-o/nlist.h: https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/nlist.h
// - xnu/osfmk/kern/cs_blobs.h: https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h

const MH_MAGIC = 0xfeedface;
const MH_CIGAM = 0xcefaedfe;
const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const MH_TWOLEVEL = 0x80;
const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;
const LC_SEGMENT = 0x1;
const LC_SYMTAB = 0x2;
const LC_LOAD_DYLIB = 0xc;
const LC_ID_DYLIB = 0xd;
const LC_LOAD_DYLINKER = 0xe;
const LC_ID_DYLINKER = 0xf;
const LC_LOAD_WEAK_DYLIB = 0x80000018;
const LC_SEGMENT_64 = 0x19;
const LC_UUID = 0x1b;
const LC_RPATH = 0x8000001c;
const LC_CODE_SIGNATURE = 0x1d;
const LC_REEXPORT_DYLIB = 0x8000001f;
const LC_LAZY_LOAD_DYLIB = 0x20;
const LC_ENCRYPTION_INFO = 0x21;
const LC_DYLD_INFO = 0x22;
const LC_DYLD_INFO_ONLY = 0x80000022;
const LC_LOAD_UPWARD_DYLIB = 0x80000023;
const LC_VERSION_MIN_MACOSX = 0x24;
const LC_VERSION_MIN_IPHONEOS = 0x25;
const LC_MAIN = 0x80000028;
const LC_SOURCE_VERSION = 0x2a;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const LC_VERSION_MIN_TVOS = 0x2f;
const LC_VERSION_MIN_WATCHOS = 0x30;
const LC_BUILD_VERSION = 0x32;
const LC_DYLD_EXPORTS_TRIE = 0x80000033;
const LC_DYLD_CHAINED_FIXUPS = 0x80000034;
const LC_FILESET_ENTRY = 0x80000035;
const N_STAB = 0xe0;
const N_PEXT = 0x10;
const N_EXT = 0x01;
const N_TYPE = 0x0e;
const N_UNDF = 0x0;
const N_INDR = 0x0a;
const N_WEAK_REF = 0x0040;
const N_WEAK_DEF = 0x0080;
const REFERENCED_DYNAMICALLY = 0x0010;
const SELF_LIBRARY_ORDINAL = 0x00;
const EXECUTABLE_ORDINAL = 0xff;
const DYNAMIC_LOOKUP_ORDINAL = 0xfe;
const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_EMBEDDED_SIGNATURE_OLD = 0xfade0b02;

export {
  CSMAGIC_CODEDIRECTORY,
  CSMAGIC_EMBEDDED_SIGNATURE,
  CSMAGIC_EMBEDDED_SIGNATURE_OLD,
  DYNAMIC_LOOKUP_ORDINAL,
  EXECUTABLE_ORDINAL,
  FAT_MAGIC,
  FAT_MAGIC_64,
  LC_BUILD_VERSION,
  LC_CODE_SIGNATURE,
  LC_DYLD_CHAINED_FIXUPS,
  LC_DYLD_EXPORTS_TRIE,
  LC_DYLD_INFO,
  LC_DYLD_INFO_ONLY,
  LC_ENCRYPTION_INFO,
  LC_ENCRYPTION_INFO_64,
  LC_FILESET_ENTRY,
  LC_ID_DYLIB,
  LC_ID_DYLINKER,
  LC_LAZY_LOAD_DYLIB,
  LC_LOAD_DYLIB,
  LC_LOAD_DYLINKER,
  LC_LOAD_UPWARD_DYLIB,
  LC_LOAD_WEAK_DYLIB,
  LC_MAIN,
  LC_REEXPORT_DYLIB,
  LC_RPATH,
  LC_SEGMENT,
  LC_SEGMENT_64,
  LC_SOURCE_VERSION,
  LC_SYMTAB,
  LC_UUID,
  LC_VERSION_MIN_IPHONEOS,
  LC_VERSION_MIN_MACOSX,
  LC_VERSION_MIN_TVOS,
  LC_VERSION_MIN_WATCHOS,
  MH_CIGAM,
  MH_CIGAM_64,
  MH_MAGIC,
  MH_MAGIC_64,
  MH_TWOLEVEL,
  N_EXT,
  N_INDR,
  N_PEXT,
  N_STAB,
  N_TYPE,
  N_UNDF,
  N_WEAK_DEF,
  N_WEAK_REF,
  REFERENCED_DYNAMICALLY,
  SELF_LIBRARY_ORDINAL
};
