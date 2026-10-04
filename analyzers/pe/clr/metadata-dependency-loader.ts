"use strict";

import { createFileRangeReader, type FileRangeReader } from "../../file-range-reader.js";
import { parsePeHeaders, isPeWindowsCore } from "../core/index.js";
import type { PeWindowsCore } from "../types.js";
import { createRvaRangeReader } from "../rva-range-reader.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import { buildCor20Issues, COR20_HEADER_SIZE_BYTES, readCor20Header } from "./cor20-header.js";
import { parseClrMetadataRoot } from "./metadata-root.js";
import type { PeClrHeader, PeClrMetadataTables } from "./types.js";

const readDependencyHeader = async (
  reader: FileRangeReader, core: PeWindowsCore, issues: string[]
): Promise<PeClrHeader | null> => {
  const directory = core.dataDirs.find(entry => entry.name === "CLR_RUNTIME");
  if (!directory?.rva || !directory.size) {
    issues.push("no CLR metadata directory was found.");
    return null;
  }
  const header = await readMappedRvaPrefix(reader, directory.rva,
    Math.min(directory.size, COR20_HEADER_SIZE_BYTES), core.rvaToOff);
  issues.push(...buildCor20Issues(directory.size, header.byteLength));
  const clr = readCor20Header(header);
  if (!clr.MetaDataRVA || !clr.MetaDataSize) {
    issues.push("CLR metadata location is absent or truncated.");
    return null;
  }
  return clr;
};

const readDependency = async (file: File, issues: string[]): Promise<PeClrMetadataTables | null> => {
  const reader = createFileRangeReader(file, 0, file.size);
  const core = await parsePeHeaders(reader);
  if (!core || !isPeWindowsCore(core)) {
    issues.push("no Windows PE headers were found.");
    return null;
  }
  const clr = await readDependencyHeader(reader, core, issues);
  if (!clr) return null;
  const metadata = await parseClrMetadataRoot(
    createRvaRangeReader(reader, core.rvaToOff, clr.MetaDataRVA, clr.MetaDataSize),
    0, clr.MetaDataSize, issues);
  if (!metadata?.tables) issues.push("CLR metadata tables are unavailable.");
  return metadata?.tables ?? null;
};

export const loadClrDependency = async (file: File, issues: string[]): Promise<PeClrMetadataTables | null> => {
  try {
    const fileIssues: string[] = [];
    const tables = await readDependency(file, fileIssues);
    issues.push(...fileIssues.map(issue => `${file.name}: ${issue}`));
    return tables;
  } catch { issues.push(`${file.name}: dependency file could not be read.`); return null; }
};
