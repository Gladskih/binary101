"use strict";

import {
  LC_BUILD_VERSION, LC_CODE_SIGNATURE, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE,
  LC_DYLD_INFO, LC_DYLD_INFO_ONLY, LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64,
  LC_FILESET_ENTRY, LC_ID_DYLIB, LC_ID_DYLINKER, LC_LAZY_LOAD_DYLIB, LC_LOAD_DYLIB,
  LC_LOAD_DYLINKER, LC_LOAD_UPWARD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_MAIN, LC_REEXPORT_DYLIB,
  LC_RPATH, LC_SEGMENT, LC_SEGMENT_64, LC_SOURCE_VERSION, LC_SYMTAB, LC_UUID,
  LC_VERSION_MIN_IPHONEOS, LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_TVOS,
  LC_VERSION_MIN_WATCHOS
} from "./commands.js";
import {
  createRangeReader,
  formatUuid,
  getMachOMagicInfo,
  parseHeader,
  subView
} from "./format.js";
import { buildTruncatedImage } from "./truncated-image.js";
import {
  parseBuildVersion, parseDylib, parseDyldInfo, parseEncryptionInfo,
  parseFileSetEntry, parseLinkeditData, parseLoadCommandRecord, parseRpath, parseSegment,
  parseStringCommand, parseVersionMin
} from "./load-command-parsers.js";
import {
  validateDyldInfoRanges,
  validateEncryptionInfoRanges,
  validateFileSetEntryRanges,
  validateLinkeditDataRanges,
  validateSegmentRanges
} from "./range-validation.js";
import { parseSymtab } from "./symbol-table.js";
import { parseCodeSignature } from "./codesign.js";
import type {
  MachOBuildVersion, MachODyldInfo, MachOEncryptionInfo, MachOFileSetEntry, MachOImage,
  MachOLinkeditData, MachOLoadCommand, MachORpath, MachOStringCommand,
  MachOSourceVersion, MachOVersionMin, MachODylib, MachOSegment,
  MachOEntryPoint
} from "./types.js";

type SymtabCommand = {
  loadCommandIndex: number;
  symoff: number;
  nsyms: number;
  stroff: number;
  strsize: number;
};

type CodeSignatureCommand = {
  loadCommandIndex: number;
  dataoff: number;
  datasize: number;
};

type EntryPointCommand = {
  loadCommandIndex: number;
  entryoff: bigint;
  stacksize: bigint;
};

const parseThinImage = async (
  file: File,
  imageOffset: number,
  imageSize: number
): Promise<MachOImage | null> => {
  const reader = createRangeReader(file, imageOffset, imageSize);
  const headerView = await reader.read(0, Math.min(imageSize, 32));
  const magicInfo = getMachOMagicInfo(headerView);
  if (!magicInfo || magicInfo.kind !== "thin") return null;
  const headerSize = magicInfo.is64 ? 32 : 28;
  if (imageSize < headerSize || headerView.byteLength < headerSize) {
    return buildTruncatedImage(
      imageOffset,
      imageSize,
      headerView,
      magicInfo,
      `Mach-O header is truncated: expected ${headerSize} bytes, got ${headerView.byteLength}.`
    );
  }
  const issues: string[] = [];
  const fullHeaderView = headerView.byteLength >= headerSize
    ? subView(headerView, 0, headerSize)
    : await reader.read(0, headerSize);
  const header = parseHeader(fullHeaderView, magicInfo);
  const availableCommandBytes = Math.max(0, imageSize - headerSize);
  const commandRegionSize = Math.min(header.sizeofcmds, availableCommandBytes);
  const commandRegionEnd = headerSize + commandRegionSize;
  if (availableCommandBytes < header.sizeofcmds) {
    issues.push(`Load-command region is truncated: expected ${header.sizeofcmds} bytes, got ${Math.max(0, imageSize - headerSize)}.`);
  }
  const loadCommands: MachOLoadCommand[] = [];
  const segments: MachOSegment[] = [];
  const dylibs: MachODylib[] = [];
  const rpaths: MachORpath[] = [];
  const stringCommands: MachOStringCommand[] = [];
  const buildVersions: MachOBuildVersion[] = [];
  const minVersions: MachOVersionMin[] = [];
  const linkeditData: MachOLinkeditData[] = [];
  const encryptionInfos: MachOEncryptionInfo[] = [];
  const fileSetEntries: MachOFileSetEntry[] = [];
  const nextSectionIndex = { value: 1 };
  let idDylib: MachODylib | null = null;
  let uuid: string | null = null;
  let sourceVersion: MachOSourceVersion | null = null;
  let entryPoint: EntryPointCommand | null = null;
  let symtabCommand: SymtabCommand | null = null;
  let dyldInfo: MachODyldInfo | null = null;
  let codeSignatureCommand: CodeSignatureCommand | null = null;
  let cursor = headerSize;
  const little = header.littleEndian;
  const loadCommandAlignment = header.is64 ? 8 : 4;
  for (let index = 0; index < header.ncmds; index += 1) {
    if (cursor + 8 > commandRegionEnd) {
      issues.push(`Load command ${index}: header extends beyond the declared load-command region.`);
      break;
    }
    const commandHeader = await reader.read(cursor, 8);
    if (commandHeader.byteLength < 8) {
      issues.push(`Load command ${index}: header extends beyond the declared load-command region.`);
      break;
    }
    const cmd = commandHeader.getUint32(0, little);
    const cmdsize = commandHeader.getUint32(4, little);
    parseLoadCommandRecord(loadCommands, imageOffset, cursor, cmd, cmdsize, index);
    if (cmdsize < 8) {
      issues.push(`Load command ${index}: invalid cmdsize ${cmdsize}.`);
      break;
    }
    if (cmdsize % loadCommandAlignment !== 0) {
      issues.push(
        `Load command ${index}: cmdsize ${cmdsize} is not aligned to ${loadCommandAlignment} bytes.`
      );
      break;
    }
    if (cursor + cmdsize > commandRegionEnd) {
      issues.push(`Load command ${index}: extends beyond the declared load-command region.`);
      break;
    }
    const cmdView = await reader.read(cursor, cmdsize);
    if (cmd === LC_SEGMENT || cmd === LC_SEGMENT_64) {
      const segment = parseSegment(cmdView, index, cmd === LC_SEGMENT_64, little, nextSectionIndex, issues);
      if (segment) segments.push(segment);
    } else if (
      cmd === LC_LOAD_DYLIB ||
      cmd === LC_ID_DYLIB ||
      cmd === LC_REEXPORT_DYLIB ||
      cmd === LC_LOAD_WEAK_DYLIB ||
      cmd === LC_LOAD_UPWARD_DYLIB ||
      cmd === LC_LAZY_LOAD_DYLIB
    ) {
      const dylib = parseDylib(cmdView, index, little, cmd, issues);
      if (dylib) {
        if (cmd === LC_ID_DYLIB) idDylib = dylib;
        else dylibs.push(dylib);
      }
    } else if (cmd === LC_RPATH) {
      const rpath = parseRpath(cmdView, index, little, issues);
      if (rpath) rpaths.push(rpath);
    } else if (cmd === LC_LOAD_DYLINKER || cmd === LC_ID_DYLINKER) {
      const stringCommand = parseStringCommand(cmdView, index, little, cmd, issues);
      if (stringCommand) stringCommands.push(stringCommand);
    } else if (cmd === LC_UUID) {
      uuid = cmdView.byteLength >= 24 ? formatUuid(cmdView, 8) : null;
      if (uuid == null) issues.push(`Load command ${index}: UUID command is truncated.`);
    } else if (cmd === LC_SYMTAB) {
      if (cmdView.byteLength < 24) issues.push(`Load command ${index}: symbol-table command is truncated.`);
      else {
        symtabCommand = {
          loadCommandIndex: index,
          symoff: cmdView.getUint32(8, little),
          nsyms: cmdView.getUint32(12, little),
          stroff: cmdView.getUint32(16, little),
          strsize: cmdView.getUint32(20, little)
        };
      }
    } else if (
      cmd === LC_CODE_SIGNATURE ||
      cmd === LC_DYLD_EXPORTS_TRIE ||
      cmd === LC_DYLD_CHAINED_FIXUPS
    ) {
      const linkedit = parseLinkeditData(cmdView, index, little, cmd, issues);
      if (linkedit) {
        linkeditData.push(linkedit);
        if (cmd === LC_CODE_SIGNATURE) {
          codeSignatureCommand = {
            loadCommandIndex: index,
            dataoff: linkedit.dataoff,
            datasize: linkedit.datasize
          };
        }
      }
    } else if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
      const encryptionInfo = parseEncryptionInfo(cmdView, index, little, cmd, issues);
      if (encryptionInfo) encryptionInfos.push(encryptionInfo);
    } else if (
      cmd === LC_VERSION_MIN_MACOSX ||
      cmd === LC_VERSION_MIN_IPHONEOS ||
      cmd === LC_VERSION_MIN_TVOS ||
      cmd === LC_VERSION_MIN_WATCHOS
    ) {
      const minimumVersion = parseVersionMin(cmdView, index, little, cmd, issues);
      if (minimumVersion) minVersions.push(minimumVersion);
    } else if (cmd === LC_BUILD_VERSION) {
      const buildVersion = parseBuildVersion(cmdView, index, little, issues);
      if (buildVersion) buildVersions.push(buildVersion);
    } else if (cmd === LC_SOURCE_VERSION) {
      if (cmdView.byteLength < 16) issues.push(`Load command ${index}: source-version command is truncated.`);
      else {
        const value = cmdView.getBigUint64(8, little);
        sourceVersion = {
          loadCommandIndex: index,
          value
        };
      }
    } else if (cmd === LC_MAIN) {
      if (cmdView.byteLength < 24) issues.push(`Load command ${index}: entry-point command is truncated.`);
      else {
        entryPoint = {
          loadCommandIndex: index,
          entryoff: cmdView.getBigUint64(8, little),
          stacksize: cmdView.getBigUint64(16, little)
        };
      }
    } else if (cmd === LC_DYLD_INFO || cmd === LC_DYLD_INFO_ONLY) {
      dyldInfo = parseDyldInfo(cmdView, index, little, cmd, issues);
    } else if (cmd === LC_FILESET_ENTRY) {
      const entry = parseFileSetEntry(cmdView, index, little, issues);
      if (entry) fileSetEntries.push(entry);
    }
    cursor += cmdsize;
  }
  const resolvedEntryPoint: MachOEntryPoint | null =
    entryPoint == null
      ? null
      : {
          loadCommandIndex: entryPoint.loadCommandIndex,
          entryoff: entryPoint.entryoff,
          stacksize: entryPoint.stacksize
        };
  validateSegmentRanges(segments, imageSize, issues);
  validateDyldInfoRanges(dyldInfo, imageSize, issues);
  validateLinkeditDataRanges(linkeditData, imageSize, issues);
  validateEncryptionInfoRanges(encryptionInfos, imageSize, issues);
  validateFileSetEntryRanges(fileSetEntries, imageSize, issues);
  const symtab = symtabCommand
    ? await parseSymtab(
        file,
        imageOffset,
        imageSize,
        header.is64,
        little,
        symtabCommand.symoff,
        symtabCommand.nsyms,
        symtabCommand.stroff,
        symtabCommand.strsize,
        header.filetype,
        header.flags
      )
    : null;
  if (symtab?.issues.length) issues.push(...symtab.issues);
  const codeSignature = codeSignatureCommand
    ? await parseCodeSignature(
        file,
        imageOffset,
        imageSize,
        codeSignatureCommand.loadCommandIndex,
        codeSignatureCommand.dataoff,
        codeSignatureCommand.datasize
      )
    : null;
  if (codeSignature?.issues.length) issues.push(...codeSignature.issues);
  return {
    offset: imageOffset,
    size: imageSize,
    header,
    loadCommands,
    segments,
    dylibs,
    idDylib,
    rpaths,
    stringCommands,
    uuid,
    buildVersions,
    minVersions,
    sourceVersion,
    entryPoint: resolvedEntryPoint,
    dyldInfo,
    linkeditData,
    encryptionInfos,
    fileSetEntries,
    symtab,
    codeSignature,
    issues
  };
};

export { parseThinImage };
