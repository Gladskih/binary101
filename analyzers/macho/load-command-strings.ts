"use strict";

import { loadCommandName } from "./load-command-info.js";

const readBoundedCommandString = (
  cmdView: DataView,
  stringOffset: number,
  minimumOffset: number,
  loadCommandIndex: number,
  fieldLabel: string,
  issues: string[]
): string => {
  if (stringOffset < minimumOffset) {
    issues.push(
      `Load command ${loadCommandIndex}: ${fieldLabel} offset ${stringOffset} points inside the fixed command fields.`
    );
    return "";
  }
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
    if (byteValue == null) break;
    if (byteValue === 0) return text;
    text += String.fromCharCode(byteValue);
  }
  issues.push(`Load command ${loadCommandIndex}: ${fieldLabel} is not NUL-terminated within cmdsize.`);
  return text;
};

const readDylibName = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  issues: string[]
): string =>
  // struct dylib_command in mach-o/loader.h is 24 bytes before the pathname.
  readBoundedCommandString(cmdView, cmdView.getUint32(8, little), 24, loadCommandIndex, "dylib name", issues);

const readFileSetEntryId = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  issues: string[]
): string =>
  // struct fileset_entry_command in mach-o/loader.h is 32 bytes before entry_id data.
  readBoundedCommandString(
    cmdView,
    cmdView.getUint32(24, little),
    32,
    loadCommandIndex,
    "fileset entry id",
    issues
  );

const readRpathValue = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  issues: string[]
): string =>
  // struct rpath_command in mach-o/loader.h is 12 bytes before the path string.
  readBoundedCommandString(cmdView, cmdView.getUint32(8, little), 12, loadCommandIndex, "rpath path", issues);

const readStringCommandValue = (
  cmdView: DataView,
  loadCommandIndex: number,
  little: boolean,
  cmd: number,
  issues: string[]
): string =>
  // struct dylinker_command in mach-o/loader.h is 12 bytes before the lc_str payload.
  readBoundedCommandString(
    cmdView,
    cmdView.getUint32(8, little),
    12,
    loadCommandIndex,
    `${loadCommandName(cmd)} string`,
    issues
  );

export {
  readDylibName,
  readFileSetEntryId,
  readRpathValue,
  readStringCommandValue
};
