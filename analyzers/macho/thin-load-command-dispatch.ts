"use strict";

import {
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
  LC_VERSION_MIN_WATCHOS
} from "./commands.js";
import { formatUuid } from "./format.js";
import {
  parseBuildVersion,
  parseDylib,
  parseDyldInfo,
  parseEncryptionInfo,
  parseFileSetEntry,
  parseLinkeditData,
  parseRpath,
  parseSegment,
  parseStringCommand,
  parseVersionMin
} from "./load-command-parsers.js";
import type { ThinLoadCommandState } from "./thin-load-command-state.js";

export const applyThinLoadCommand = (
  cmdView: DataView,
  cmd: number,
  index: number,
  little: boolean,
  state: ThinLoadCommandState,
  issues: string[]
): void => {
  if (cmd === LC_SEGMENT || cmd === LC_SEGMENT_64) {
    const segment = parseSegment(cmdView, index, cmd === LC_SEGMENT_64, little, state.nextSectionIndex, issues);
    if (segment) state.segments.push(segment);
    return;
  }
  if (isDylibCommand(cmd)) {
    recordDylibCommand(cmdView, cmd, index, little, state, issues);
    return;
  }
  if (cmd === LC_RPATH) {
    const rpath = parseRpath(cmdView, index, little, issues);
    if (rpath) state.rpaths.push(rpath);
    return;
  }
  if (cmd === LC_LOAD_DYLINKER || cmd === LC_ID_DYLINKER) {
    const stringCommand = parseStringCommand(cmdView, index, little, cmd, issues);
    if (stringCommand) state.stringCommands.push(stringCommand);
    return;
  }
  applyThinMetadataCommand(cmdView, cmd, index, little, state, issues);
};

const isDylibCommand = (cmd: number): boolean =>
  cmd === LC_LOAD_DYLIB ||
  cmd === LC_ID_DYLIB ||
  cmd === LC_REEXPORT_DYLIB ||
  cmd === LC_LOAD_WEAK_DYLIB ||
  cmd === LC_LOAD_UPWARD_DYLIB ||
  cmd === LC_LAZY_LOAD_DYLIB;

const recordDylibCommand = (
  cmdView: DataView,
  cmd: number,
  index: number,
  little: boolean,
  state: ThinLoadCommandState,
  issues: string[]
): void => {
  const dylib = parseDylib(cmdView, index, little, cmd, issues);
  if (!dylib) return;
  if (cmd === LC_ID_DYLIB) state.idDylib = dylib;
  else state.dylibs.push(dylib);
};

const applyThinMetadataCommand = (
  cmdView: DataView,
  cmd: number,
  index: number,
  little: boolean,
  state: ThinLoadCommandState,
  issues: string[]
): void => {
  if (cmd === LC_UUID) recordUuidCommand(cmdView, index, state, issues);
  else if (cmd === LC_SYMTAB) recordSymtabCommand(cmdView, index, little, state, issues);
  else if (isLinkeditDataCommand(cmd)) recordLinkeditCommand(cmdView, cmd, index, little, state, issues);
  else if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
    const encryptionInfo = parseEncryptionInfo(cmdView, index, little, cmd, issues);
    if (encryptionInfo) state.encryptionInfos.push(encryptionInfo);
  } else if (isMinimumVersionCommand(cmd)) {
    const minimumVersion = parseVersionMin(cmdView, index, little, cmd, issues);
    if (minimumVersion) state.minVersions.push(minimumVersion);
  } else if (cmd === LC_BUILD_VERSION) recordBuildVersionCommand(cmdView, index, little, state, issues);
  else if (cmd === LC_SOURCE_VERSION) recordSourceVersionCommand(cmdView, index, little, state, issues);
  else if (cmd === LC_MAIN) recordEntryPointCommand(cmdView, index, little, state, issues);
  else if (cmd === LC_DYLD_INFO || cmd === LC_DYLD_INFO_ONLY) {
    state.dyldInfo = parseDyldInfo(cmdView, index, little, cmd, issues);
  } else if (cmd === LC_FILESET_ENTRY) {
    const entry = parseFileSetEntry(cmdView, index, little, issues);
    if (entry) state.fileSetEntries.push(entry);
  }
};

const recordUuidCommand = (
  cmdView: DataView,
  index: number,
  state: ThinLoadCommandState,
  issues: string[]
): void => {
  state.uuid = cmdView.byteLength >= 24 ? formatUuid(cmdView, 8) : null;
  if (state.uuid == null) issues.push(`Load command ${index}: UUID command is truncated.`);
};

const recordSymtabCommand = (
  cmdView: DataView,
  index: number,
  little: boolean,
  state: ThinLoadCommandState,
  issues: string[]
): void => {
  if (cmdView.byteLength < 24) {
    issues.push(`Load command ${index}: symbol-table command is truncated.`);
    return;
  }
  state.symtabCommand = {
    loadCommandIndex: index,
    symoff: cmdView.getUint32(8, little),
    nsyms: cmdView.getUint32(12, little),
    stroff: cmdView.getUint32(16, little),
    strsize: cmdView.getUint32(20, little)
  };
};

const isLinkeditDataCommand = (cmd: number): boolean =>
  cmd === LC_CODE_SIGNATURE ||
  cmd === LC_DYLD_EXPORTS_TRIE ||
  cmd === LC_DYLD_CHAINED_FIXUPS;

const recordLinkeditCommand = (
  cmdView: DataView,
  cmd: number,
  index: number,
  little: boolean,
  state: ThinLoadCommandState,
  issues: string[]
): void => {
  const linkedit = parseLinkeditData(cmdView, index, little, cmd, issues);
  if (!linkedit) return;
  state.linkeditData.push(linkedit);
  if (cmd === LC_CODE_SIGNATURE) {
    state.codeSignatureCommand = {
      loadCommandIndex: index,
      dataoff: linkedit.dataoff,
      datasize: linkedit.datasize
    };
  }
};

const isMinimumVersionCommand = (cmd: number): boolean =>
  cmd === LC_VERSION_MIN_MACOSX ||
  cmd === LC_VERSION_MIN_IPHONEOS ||
  cmd === LC_VERSION_MIN_TVOS ||
  cmd === LC_VERSION_MIN_WATCHOS;

const recordBuildVersionCommand = (
  cmdView: DataView,
  index: number,
  little: boolean,
  state: ThinLoadCommandState,
  issues: string[]
): void => {
  const buildVersion = parseBuildVersion(cmdView, index, little, issues);
  if (buildVersion) state.buildVersions.push(buildVersion);
};

const recordSourceVersionCommand = (
  cmdView: DataView,
  index: number,
  little: boolean,
  state: ThinLoadCommandState,
  issues: string[]
): void => {
  if (cmdView.byteLength < 16) {
    issues.push(`Load command ${index}: source-version command is truncated.`);
    return;
  }
  state.sourceVersion = {
    loadCommandIndex: index,
    value: cmdView.getBigUint64(8, little)
  };
};

const recordEntryPointCommand = (
  cmdView: DataView,
  index: number,
  little: boolean,
  state: ThinLoadCommandState,
  issues: string[]
): void => {
  if (cmdView.byteLength < 24) {
    issues.push(`Load command ${index}: entry-point command is truncated.`);
    return;
  }
  state.entryPoint = {
    loadCommandIndex: index,
    entryoff: cmdView.getBigUint64(8, little),
    stacksize: cmdView.getBigUint64(16, little)
  };
};
