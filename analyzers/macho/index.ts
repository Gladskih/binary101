"use strict";

import { getMachOMagicInfo, readRange } from "./format.js";
import { parseFatBinary } from "./fat.js";
import { probeMachO } from "./probe.js";
import { parseThinImage } from "./thin.js";
import type { MachOParseResult } from "./types.js";

const parseMachO = async (file: File): Promise<MachOParseResult | null> => {
  const probeView = await readRange(file, 0, Math.min(file.size, 32));
  if (!probeMachO(probeView, file.size)) return null;
  const magicInfo = getMachOMagicInfo(probeView);
  if (!magicInfo) return null;
  if (magicInfo.kind === "fat") {
    return parseFatBinary(file, magicInfo);
  }
  const image = await parseThinImage(file, 0, file.size);
  if (!image) return null;
  return {
    kind: "thin",
    fileSize: file.size,
    image,
    fatHeader: null,
    slices: [],
    issues: image.issues
  };
};

export { parseMachO };
export type { MachOParseResult } from "./types.js";
