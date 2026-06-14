"use strict";

import {
  createRangeReader,
  getMachOMagicInfo,
  parseHeader,
  subView
} from "./format.js";
import { buildTruncatedImage } from "./truncated-image.js";
import { parseThinExternalData } from "./thin-external-data.js";
import {
  collectThinLoadCommands,
  validateThinLoadCommandRanges
} from "./thin-load-command-collection.js";
import {
  buildThinImage,
  createThinLoadCommandState
} from "./thin-load-command-state.js";
import type { MachOFileHeader, MachOImage } from "./types.js";

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
  const header = parseHeader(await readFullHeader(reader, headerView, headerSize), magicInfo);
  const commandRegionEnd = getCommandRegionEnd(header, headerSize, imageSize, issues);
  const state = createThinLoadCommandState();
  await collectThinLoadCommands(reader, imageOffset, headerSize, header, commandRegionEnd, state, issues);
  validateThinLoadCommandRanges(state, imageSize, issues);
  const externalData = await parseThinExternalData(file, imageOffset, imageSize, header, state, issues);
  return buildThinImage(imageOffset, imageSize, header, state, externalData, issues);
};

const readFullHeader = async (
  reader: ReturnType<typeof createRangeReader>,
  headerView: DataView,
  headerSize: number
): Promise<DataView> =>
  headerView.byteLength >= headerSize
    ? subView(headerView, 0, headerSize)
    : reader.read(0, headerSize);

const getCommandRegionEnd = (
  header: MachOFileHeader,
  headerSize: number,
  imageSize: number,
  issues: string[]
): number => {
  const availableCommandBytes = Math.max(0, imageSize - headerSize);
  if (availableCommandBytes < header.sizeofcmds) {
    issues.push(
      `Load-command region is truncated: expected ${header.sizeofcmds} bytes, got ${availableCommandBytes}.`
    );
  }
  return headerSize + Math.min(header.sizeofcmds, availableCommandBytes);
};

export { parseThinImage };
