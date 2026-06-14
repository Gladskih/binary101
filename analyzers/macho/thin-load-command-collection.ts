"use strict";

import type { MachORangeReader } from "./format.js";
import { parseLoadCommandRecord } from "./load-command-parsers.js";
import { noteDuplicateSingletonCommand } from "./load-command-singletons.js";
import {
  validateDyldInfoRanges,
  validateEncryptionInfoRanges,
  validateFileSetEntryRanges,
  validateLinkeditDataRanges,
  validateSegmentRanges
} from "./range-validation.js";
import { applyThinLoadCommand } from "./thin-load-command-dispatch.js";
import type { ThinLoadCommandState } from "./thin-load-command-state.js";
import type { MachOFileHeader } from "./types.js";

type LoadCommandHeader = {
  cmd: number;
  cmdsize: number;
};

export const collectThinLoadCommands = async (
  reader: MachORangeReader,
  imageOffset: number,
  headerSize: number,
  header: MachOFileHeader,
  commandRegionEnd: number,
  state: ThinLoadCommandState,
  issues: string[]
): Promise<void> => {
  let cursor = headerSize;
  const little = header.littleEndian;
  const loadCommandAlignment = header.is64 ? 8 : 4;
  for (let index = 0; index < header.ncmds; index += 1) {
    const commandHeader = await readThinLoadCommandHeader(
      reader,
      cursor,
      commandRegionEnd,
      little,
      index,
      issues
    );
    if (!commandHeader) break;
    parseLoadCommandRecord(
      state.loadCommands,
      imageOffset,
      cursor,
      commandHeader.cmd,
      commandHeader.cmdsize,
      index
    );
    noteDuplicateSingletonCommand(state.seenSingletonCommands, commandHeader.cmd, index, issues);
    if (!isThinLoadCommandSizeValid(
      index,
      cursor,
      commandHeader.cmdsize,
      loadCommandAlignment,
      commandRegionEnd,
      issues
    )) break;
    applyThinLoadCommand(
      await reader.read(cursor, commandHeader.cmdsize),
      commandHeader.cmd,
      index,
      little,
      state,
      issues
    );
    cursor += commandHeader.cmdsize;
  }
};

export const validateThinLoadCommandRanges = (
  state: ThinLoadCommandState,
  imageSize: number,
  issues: string[]
): void => {
  validateSegmentRanges(state.segments, imageSize, issues);
  validateDyldInfoRanges(state.dyldInfo, imageSize, issues);
  validateLinkeditDataRanges(state.linkeditData, imageSize, issues);
  validateEncryptionInfoRanges(state.encryptionInfos, imageSize, issues);
  validateFileSetEntryRanges(state.fileSetEntries, imageSize, issues);
};

const readThinLoadCommandHeader = async (
  reader: MachORangeReader,
  cursor: number,
  commandRegionEnd: number,
  little: boolean,
  index: number,
  issues: string[]
): Promise<LoadCommandHeader | null> => {
  if (cursor + 8 > commandRegionEnd) {
    issues.push(`Load command ${index}: header extends beyond the declared load-command region.`);
    return null;
  }
  const commandHeader = await reader.read(cursor, 8);
  if (commandHeader.byteLength < 8) {
    issues.push(`Load command ${index}: header extends beyond the declared load-command region.`);
    return null;
  }
  return {
    cmd: commandHeader.getUint32(0, little),
    cmdsize: commandHeader.getUint32(4, little)
  };
};

const isThinLoadCommandSizeValid = (
  index: number,
  cursor: number,
  cmdsize: number,
  loadCommandAlignment: number,
  commandRegionEnd: number,
  issues: string[]
): boolean => {
  if (cmdsize < 8) {
    issues.push(`Load command ${index}: invalid cmdsize ${cmdsize}.`);
    return false;
  }
  if (cmdsize % loadCommandAlignment !== 0) {
    issues.push(
      `Load command ${index}: cmdsize ${cmdsize} is not aligned to ${loadCommandAlignment} bytes.`
    );
    return false;
  }
  if (cursor + cmdsize > commandRegionEnd) {
    issues.push(`Load command ${index}: extends beyond the declared load-command region.`);
    return false;
  }
  return true;
};
