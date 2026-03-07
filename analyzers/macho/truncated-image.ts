"use strict";

import { thinMagicValue } from "./format.js";
import type { getMachOMagicInfo } from "./format.js";
import type { MachOImage } from "./types.js";

const readHeaderUint32 = (view: DataView, offset: number, little: boolean): number =>
  offset + 4 <= view.byteLength ? view.getUint32(offset, little) : 0;

const buildTruncatedImage = (
  imageOffset: number,
  imageSize: number,
  headerView: DataView,
  magicInfo: NonNullable<ReturnType<typeof getMachOMagicInfo>>,
  issue: string
): MachOImage => {
  const little = magicInfo.littleEndian;
  return {
    offset: imageOffset,
    size: imageSize,
    header: {
      magic: thinMagicValue(magicInfo.is64),
      is64: magicInfo.is64,
      littleEndian: little,
      cputype: readHeaderUint32(headerView, 4, little),
      cpusubtype: readHeaderUint32(headerView, 8, little),
      filetype: readHeaderUint32(headerView, 12, little),
      ncmds: readHeaderUint32(headerView, 16, little),
      sizeofcmds: readHeaderUint32(headerView, 20, little),
      flags: readHeaderUint32(headerView, 24, little),
      reserved: magicInfo.is64 ? readHeaderUint32(headerView, 28, little) : null
    },
    loadCommands: [],
    segments: [],
    dylibs: [],
    idDylib: null,
    rpaths: [],
    stringCommands: [],
    uuid: null,
    buildVersions: [],
    minVersions: [],
    sourceVersion: null,
    entryPoint: null,
    dyldInfo: null,
    linkeditData: [],
    encryptionInfos: [],
    fileSetEntries: [],
    symtab: null,
    codeSignature: null,
    issues: [issue]
  };
};

export { buildTruncatedImage };
