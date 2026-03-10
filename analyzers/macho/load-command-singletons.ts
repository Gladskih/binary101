"use strict";

import {
  LC_CODE_SIGNATURE,
  LC_DYLD_INFO,
  LC_DYLD_INFO_ONLY,
  LC_ID_DYLIB,
  LC_ID_DYLINKER,
  LC_MAIN,
  LC_SOURCE_VERSION,
  LC_SYMTAB,
  LC_UUID
} from "./commands.js";
import { loadCommandName } from "./load-command-info.js";

// LC_DYLD_INFO and LC_DYLD_INFO_ONLY describe the same singleton dyld-info slot
// in mach-o/loader.h, so treat them as one duplicate-detection group.
const duplicateDyldInfoIdentity = Symbol("duplicateDyldInfoIdentity");

const singletonLoadCommandInfo = (
  cmd: number
): { identity: number | symbol; label: string } | null => {
  switch (cmd) {
    case LC_CODE_SIGNATURE:
    case LC_ID_DYLIB:
    case LC_ID_DYLINKER:
    case LC_MAIN:
    case LC_SOURCE_VERSION:
    case LC_SYMTAB:
    case LC_UUID:
      return {
        identity: cmd,
        label: loadCommandName(cmd)
      };
    case LC_DYLD_INFO:
    case LC_DYLD_INFO_ONLY:
      return {
        identity: duplicateDyldInfoIdentity,
        label: "LC_DYLD_INFO/LC_DYLD_INFO_ONLY"
      };
    default:
      return null;
  }
};

const noteDuplicateSingletonCommand = (
  seenSingletonCommands: Map<number | symbol, number>,
  cmd: number,
  index: number,
  issues: string[]
): void => {
  const info = singletonLoadCommandInfo(cmd);
  if (info == null) return;
  const previousIndex = seenSingletonCommands.get(info.identity);
  if (previousIndex != null) {
    issues.push(
      `Load command ${index}: multiple ${info.label} commands found; ` +
        `earlier entry at load command ${previousIndex}.`
    );
    return;
  }
  seenSingletonCommands.set(info.identity, index);
};

export { noteDuplicateSingletonCommand };
