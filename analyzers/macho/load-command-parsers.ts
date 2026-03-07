"use strict";

import {
  loadCommandName
} from "./load-command-info.js";
import type {
  MachOBuildTool,
  MachOBuildVersion,
  MachODylib,
  MachODyldInfo,
  MachOEncryptionInfo,
  MachOFileSetEntry,
  MachOLinkeditData,
  MachOLoadCommand,
  MachORpath,
  MachOStringCommand,
  MachOVersionMin
} from "./types.js";
import { parseSegment } from "./segment-parser.js";

const parseLoadCommandRecord = (
  loadCommands: MachOLoadCommand[],
  imageOffset: number,
  cursor: number,
  cmd: number,
  cmdsize: number,
  index: number
): void => {
  loadCommands.push({
    index,
    offset: imageOffset + cursor,
    cmd,
    cmdsize
  });
};

const readBoundedCommandString = (
  cmdView: DataView,
  stringOffset: number,
  loadCommandIndex: number,
  fieldLabel: string,
  issues: string[]
): string => {
  if (stringOffset >= cmdView.byteLength) {
    issues.push(
      `Load command ${loadCommandIndex}: ${fieldLabel} offset ${stringOffset} points outside the command.`
    );
    return "";
  }
  const bytes = new Uint8Array(cmdView.buffer, cmdView.byteOffset, cmdView.byteLength);
  let text = "";
  for (let index = stringOffset; index < bytes.length; index += 1) {
    const byteValue = bytes[index];
    if (byteValue === 0) return text;
    text += String.fromCharCode(byteValue);
  }
  issues.push(`Load command ${loadCommandIndex}: ${fieldLabel} is not NUL-terminated within cmdsize.`);
  return text;
};

const parseDylib = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  cmd: number,
  issues: string[]
): MachODylib | null => {
  if (cmdView.byteLength < 24) {
    issues.push(`Load command ${loadCommandIndex}: dylib command is truncated.`);
    return null;
  }
  return {
    loadCommandIndex,
    command: cmd,
    name: readBoundedCommandString(
      cmdView,
      cmdView.getUint32(8, little),
      loadCommandIndex,
      "dylib name",
      issues
    ),
    timestamp: cmdView.getUint32(12, little),
    currentVersion: cmdView.getUint32(16, little),
    compatibilityVersion: cmdView.getUint32(20, little)
  };
};

const parseVersionMin = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  cmd: number,
  issues: string[]
): MachOVersionMin | null => {
  if (cmdView.byteLength < 16) {
    issues.push(`Load command ${loadCommandIndex}: minimum-version command is truncated.`);
    return null;
  }
  const version = cmdView.getUint32(8, little);
  const sdk = cmdView.getUint32(12, little);
  return {
    loadCommandIndex,
    command: cmd,
    version,
    sdk
  };
};

const parseBuildVersion = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  issues: string[]
): MachOBuildVersion | null => {
  if (cmdView.byteLength < 24) {
    issues.push(`Load command ${loadCommandIndex}: build-version command is truncated.`);
    return null;
  }
  const ntools = cmdView.getUint32(20, little);
  const availableTools = Math.floor(Math.max(0, cmdView.byteLength - 24) / 8);
  if (availableTools < ntools) {
    issues.push(`Load command ${loadCommandIndex}: build-version command is missing ${ntools - availableTools} tool entries.`);
  }
  const tools: MachOBuildTool[] = [];
  for (let toolIndex = 0; toolIndex < Math.min(ntools, availableTools); toolIndex += 1) {
    const toolOffset = 24 + toolIndex * 8;
    const tool = cmdView.getUint32(toolOffset, little);
    const version = cmdView.getUint32(toolOffset + 4, little);
    tools.push({
      tool,
      version
    });
  }
  return {
    loadCommandIndex,
    platform: cmdView.getUint32(8, little),
    minos: cmdView.getUint32(12, little),
    sdk: cmdView.getUint32(16, little),
    tools
  };
};

const parseDyldInfo = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  cmd: number,
  issues: string[]
): MachODyldInfo | null => {
  if (cmdView.byteLength < 48) {
    issues.push(`Load command ${loadCommandIndex}: ${loadCommandName(cmd)} is truncated.`);
    return null;
  }
  return {
    loadCommandIndex,
    command: cmd,
    rebaseOff: cmdView.getUint32(8, little),
    rebaseSize: cmdView.getUint32(12, little),
    bindOff: cmdView.getUint32(16, little),
    bindSize: cmdView.getUint32(20, little),
    weakBindOff: cmdView.getUint32(24, little),
    weakBindSize: cmdView.getUint32(28, little),
    lazyBindOff: cmdView.getUint32(32, little),
    lazyBindSize: cmdView.getUint32(36, little),
    exportOff: cmdView.getUint32(40, little),
    exportSize: cmdView.getUint32(44, little)
  };
};

const parseLinkeditData = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  cmd: number,
  issues: string[]
): MachOLinkeditData | null => {
  if (cmdView.byteLength < 16) {
    issues.push(`Load command ${loadCommandIndex}: ${loadCommandName(cmd)} is truncated.`);
    return null;
  }
  return {
    loadCommandIndex,
    command: cmd,
    dataoff: cmdView.getUint32(8, little),
    datasize: cmdView.getUint32(12, little)
  };
};

const parseEncryptionInfo = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  cmd: number,
  issues: string[]
): MachOEncryptionInfo | null => {
  if (cmdView.byteLength < 20) {
    issues.push(`Load command ${loadCommandIndex}: ${loadCommandName(cmd)} is truncated.`);
    return null;
  }
  return {
    loadCommandIndex,
    command: cmd,
    cryptoff: cmdView.getUint32(8, little),
    cryptsize: cmdView.getUint32(12, little),
    cryptid: cmdView.getUint32(16, little)
  };
};

const parseFileSetEntry = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  issues: string[]
): MachOFileSetEntry | null => {
  if (cmdView.byteLength < 32) {
    issues.push(`Load command ${loadCommandIndex}: fileset entry command is truncated.`);
    return null;
  }
  return {
    loadCommandIndex,
    entryId: readBoundedCommandString(
      cmdView,
      cmdView.getUint32(24, little),
      loadCommandIndex,
      "fileset entry id",
      issues
    ),
    vmaddr: cmdView.getBigUint64(8, little),
    fileoff: cmdView.getBigUint64(16, little)
  };
};

const parseRpath = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  issues: string[]
): MachORpath | null => {
  if (cmdView.byteLength < 12) {
    issues.push(`Load command ${loadCommandIndex}: LC_RPATH is truncated.`);
    return null;
  }
  return {
    loadCommandIndex,
    path: readBoundedCommandString(
      cmdView,
      cmdView.getUint32(8, little),
      loadCommandIndex,
      "rpath path",
      issues
    )
  };
};

const parseStringCommand = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  cmd: number,
  issues: string[]
): MachOStringCommand | null => {
  if (cmdView.byteLength < 12) {
    issues.push(`Load command ${loadCommandIndex}: ${loadCommandName(cmd)} is truncated.`);
    return null;
  }
  return {
    loadCommandIndex,
    command: cmd,
    value: readBoundedCommandString(
      cmdView,
      cmdView.getUint32(8, little),
      loadCommandIndex,
      `${loadCommandName(cmd)} string`,
      issues
    )
  };
};

export {
  parseBuildVersion,
  parseDylib,
  parseDyldInfo,
  parseEncryptionInfo,
  parseFileSetEntry,
  parseLinkeditData,
  parseLoadCommandRecord,
  parseRpath,
  parseSegment,
  parseStringCommand,
  parseVersionMin
};
