"use strict";

import {
  LC_CODE_SIGNATURE,
  LC_ID_DYLIB,
  LC_LOAD_DYLIB,
  LC_LOAD_DYLINKER,
  LC_MAIN,
  LC_RPATH,
  LC_UUID,
  LC_VERSION_MIN_WATCHOS
} from "../../analyzers/macho/commands.js";
import type { MachOImage } from "../../analyzers/macho/types.js";

const createRendererMachOImage = (): MachOImage => ({
  offset: 0,
  size: 0x3000,
  header: {
    magic: 0xfeedfacf,
    is64: true,
    littleEndian: true,
    cputype: 0x0100000c,
    cpusubtype: 2,
    filetype: 6,
    ncmds: 4,
    sizeofcmds: 0x120,
    flags: 0x00200000,
    reserved: 0
  },
  loadCommands: [
    { index: 0, offset: 0x20, cmd: LC_LOAD_DYLINKER, cmdsize: 24 },
    { index: 1, offset: 0x38, cmd: LC_MAIN, cmdsize: 24 },
    { index: 2, offset: 0x50, cmd: LC_UUID, cmdsize: 24 },
    { index: 3, offset: 0x68, cmd: LC_RPATH, cmdsize: 24 }
  ],
  segments: [
    {
      loadCommandIndex: 0,
      name: "__TEXT",
      vmaddr: 0x1000n,
      vmsize: 0x1000n,
      fileoff: 0n,
      filesize: 0x800n,
      maxprot: 7,
      initprot: 5,
      nsects: 1,
      flags: 0x1,
      sections: [
        {
          index: 1,
          segmentName: "__TEXT",
          sectionName: "__text",
          addr: 0x1000n,
          size: 0x40n,
          offset: 0x200,
          align: 4,
          reloff: 0,
          nreloc: 0,
          flags: 0x80000400,
          reserved1: 0,
          reserved2: 0,
          reserved3: 0
        }
      ]
    }
  ],
  dylibs: [
    {
      loadCommandIndex: 1,
      command: LC_LOAD_DYLIB,
      name: "/usr/lib/libSystem.B.dylib",
      timestamp: 0,
      currentVersion: 0x10000,
      compatibilityVersion: 0x10000
    }
  ],
  idDylib: {
    loadCommandIndex: 2,
    command: LC_ID_DYLIB,
    name: "@rpath/libExample.dylib",
    timestamp: 0,
    currentVersion: 0x10000,
    compatibilityVersion: 0x10000
  },
  rpaths: [{ loadCommandIndex: 3, path: "@executable_path/Frameworks" }],
  stringCommands: [
    { loadCommandIndex: 0, command: LC_LOAD_DYLINKER, value: "/usr/lib/dyld" }
  ],
  uuid: "00112233-4455-6677-8899-aabbccddeeff",
  buildVersions: [
    {
      loadCommandIndex: 0,
      platform: 11,
      minos: 0x00010000,
      sdk: 0x00010000,
      tools: [{ tool: 1024, version: 0x10203 }]
    }
  ],
  minVersions: [
    {
      loadCommandIndex: 1,
      command: LC_VERSION_MIN_WATCHOS,
      version: 0x00050000,
      sdk: 0x00060000
    }
  ],
  sourceVersion: { loadCommandIndex: 2, value: 0x0102030405n },
  entryPoint: { loadCommandIndex: 1, entryoff: 0x2000n, stacksize: 0x4000n },
  dyldInfo: {
    loadCommandIndex: 3,
    command: 0x22,
    rebaseOff: 1,
    rebaseSize: 2,
    bindOff: 3,
    bindSize: 4,
    weakBindOff: 5,
    weakBindSize: 6,
    lazyBindOff: 7,
    lazyBindSize: 8,
    exportOff: 9,
    exportSize: 10
  },
  linkeditData: [
    { loadCommandIndex: 4, command: LC_CODE_SIGNATURE, dataoff: 0x2800, datasize: 0x80 }
  ],
  encryptionInfos: [
    { loadCommandIndex: 5, command: 0x2c, cryptoff: 0x200, cryptsize: 0x40, cryptid: 1 }
  ],
  fileSetEntries: [
    { loadCommandIndex: 6, entryId: "kernelcache", vmaddr: 0x1000n, fileoff: 0x200n }
  ],
  symtab: null,
  codeSignature: null,
  issues: ["entry point is not mapped by the parsed segments"]
});

export { createRendererMachOImage };
