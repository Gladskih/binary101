"use strict";

import { parsePeHeaders, isPeWindowsCore } from "../../analyzers/pe/core/index.js";
import { parseClrDirectory } from "../../analyzers/pe/clr/index.js";
import { parseExportDirectory } from "../../analyzers/pe/directories/exports.js";
import { parseBaseRelocations } from "../../analyzers/pe/directories/reloc.js";
import { analyzePeNativeAotMetadata } from "../../analyzers/pe/native-aot-metadata.js";
import { detectNativeAotCandidate } from "../../analyzers/pe/native-aot.js";
import type { FileRangeReader } from "../../analyzers/file-range-reader.js";
import { openDiskFileRangeReader } from "../disk-file-range-reader.js";

export type NativeAotDiskMatch = {
  path: string;
  sizeBytes: number;
  status: "candidate" | "confirmed";
};

export type NativeAotDiskScanResult = {
  match: NativeAotDiskMatch | null;
  pe: boolean;
};

export const scanNativeAotReader = async (
  reader: FileRangeReader,
  path: string,
  sizeBytes: number
): Promise<NativeAotDiskScanResult> => {
  const core = await parsePeHeaders(reader);
  if (!core || !isPeWindowsCore(core)) return { match: null, pe: false };
  const [clr, exportsInfo, relocations] = await Promise.all([
    parseClrDirectory(reader, core.dataDirs, core.rvaToOff),
    parseExportDirectory(reader, core.dataDirs, core.rvaToOff),
    parseBaseRelocations(reader, core.dataDirs, core.rvaToOff)
  ]);
  const metadata = clr == null
    ? await analyzePeNativeAotMetadata(reader, core, relocations)
    : null;
  const nativeAot = metadata ?? detectNativeAotCandidate(clr != null, exportsInfo, core.sections);
  return {
    pe: true,
    match: nativeAot ? { path, sizeBytes, status: nativeAot.status } : null
  };
};

export const scanNativeAotDiskFile = async (
  path: string,
  sizeBytes: number
): Promise<NativeAotDiskScanResult> => {
  const diskFile = await openDiskFileRangeReader(path, sizeBytes);
  try {
    return await scanNativeAotReader(diskFile.reader, path, sizeBytes);
  } finally {
    await diskFile.close();
  }
};
