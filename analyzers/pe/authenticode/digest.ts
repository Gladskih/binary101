"use strict";

import { bufferToHex } from "../../../binary-utils.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { AuthenticodeInfo } from "./index.js";
import {
  computeDigest,
  resolveDigestAlgorithmByName,
  resolveDigestAlgorithmByOid
} from "./digest-algorithms.js";
import type { PeCore, PeDataDirectory, PeSection, PeWindowsOptionalHeader } from "../types.js";

export type DigestFunction = (algorithm: AlgorithmIdentifier, data: ArrayBuffer) => Promise<ArrayBuffer>;
export type DigestLookup = (algorithm: AlgorithmIdentifier) => Promise<string | null>;
export type PeAuthenticodeBestEffortCore = Pick<PeCore, "optOff" | "ddStartRel" | "dataDirs">;
export type PeAuthenticodeParsedCore = PeAuthenticodeBestEffortCore & {
  opt: Pick<PeWindowsOptionalHeader, "SizeOfHeaders">;
  sections: PeSection[];
};

type FileByteRange = { start: number; end: number };

const resolveAuthenticodeHash = (auth: AuthenticodeInfo): AlgorithmIdentifier | null => {
  const raw =
    auth.fileDigestAlgorithmName ||
    auth.fileDigestAlgorithm ||
    (auth.digestAlgorithms?.length === 1 ? auth.digestAlgorithms[0] : undefined);
  if (!raw) return null;
  return resolveDigestAlgorithmByName(raw) ?? resolveDigestAlgorithmByOid(raw) ?? null;
};

const pushRange = (ranges: FileByteRange[], reader: FileRangeReader, start: number, end: number): void => {
  const safeStart = Math.max(0, Math.min(start, reader.size));
  const safeEnd = Math.max(0, Math.min(end, reader.size));
  if (safeEnd > safeStart) ranges.push({ start: safeStart, end: safeEnd });
};

const pushRangeExcludingRange = (
  ranges: FileByteRange[],
  reader: FileRangeReader,
  start: number,
  end: number,
  excludedStart: number,
  excludedEnd: number
): void => {
  const safeStart = Math.max(0, Math.min(start, reader.size));
  const safeEnd = Math.max(0, Math.min(end, reader.size));
  if (safeEnd <= safeStart) return;
  if (excludedEnd <= safeStart || excludedStart >= safeEnd) {
    pushRange(ranges, reader, safeStart, safeEnd);
    return;
  }
  pushRange(ranges, reader, safeStart, Math.max(safeStart, excludedStart));
  pushRange(ranges, reader, Math.min(safeEnd, excludedEnd), safeEnd);
};

const compareSectionHashOrder = (left: PeSection, right: PeSection): number => {
  // Microsoft Authenticode PE signature format, "Calculating the PE Image Hash":
  // section data is sorted by IMAGE_SECTION_HEADER.PointerToRawData before hashing.
  return (left.pointerToRawData >>> 0) - (right.pointerToRawData >>> 0) ||
    (left.virtualAddress >>> 0) - (right.virtualAddress >>> 0);
};

const listSectionHashRegions = (
  fileSize: number,
  sections: PeSection[]
): Array<{ start: number; end: number }> =>
  sections
    .filter(section => (section.sizeOfRawData >>> 0) > 0)
    .slice()
    .sort(compareSectionHashOrder)
    .map(section => {
      const start = section.pointerToRawData >>> 0;
      const end = Math.min(fileSize, start + (section.sizeOfRawData >>> 0));
      return { start, end };
    })
    .filter(region => region.end > region.start);

const computeHeaderHashEnd = (
  fileSize: number,
  sizeOfHeaders: number,
  afterSecurityEntry: number,
  sections: PeSection[]
): number => {
  const sectionRegions = listSectionHashRegions(fileSize, sections);
  const firstSectionStart =
    sectionRegions.length ? Math.min(...sectionRegions.map(region => region.start)) : undefined;
  const normalizedHeadersSize =
    Number.isSafeInteger(sizeOfHeaders) && sizeOfHeaders > 0 ? Math.min(fileSize, sizeOfHeaders) : fileSize;
  const limitedHeaderEnd =
    firstSectionStart != null ? Math.min(normalizedHeadersSize, firstSectionStart) : normalizedHeadersSize;
  return Math.max(afterSecurityEntry, limitedHeaderEnd);
};

const hasParsedPeHashContext = (
  core: PeAuthenticodeBestEffortCore | PeAuthenticodeParsedCore
): core is PeAuthenticodeParsedCore =>
  Array.isArray((core as Partial<PeAuthenticodeParsedCore>).sections) &&
  typeof (core as Partial<PeAuthenticodeParsedCore>).opt?.SizeOfHeaders === "number";

const readRanges = async (reader: FileRangeReader, ranges: FileByteRange[]): Promise<ArrayBuffer> => {
  if (!reader.readInto) throw new Error("FileRangeReader does not support direct range reads");
  const totalLength = ranges.reduce((total, range) => total + range.end - range.start, 0);
  let out = new Uint8Array(totalLength);
  let outputOffset = 0;
  for (const range of ranges) {
    const rangeLength = range.end - range.start;
    const filled = await reader.readInto(
      range.start,
      out.subarray(outputOffset, outputOffset + rangeLength)
    );
    out = new Uint8Array(filled.buffer);
    outputOffset += filled.byteLength;
  }
  return outputOffset === out.byteLength ? out.buffer : out.slice(0, outputOffset).buffer;
};

export const computePeAuthenticodeDigestBestEffort = async (
  reader: FileRangeReader,
  core: PeAuthenticodeBestEffortCore,
  securityDir: PeDataDirectory | undefined,
  algorithm: AlgorithmIdentifier,
  digestFunction?: DigestFunction
): Promise<string | null> => {
  const checksumOff = core.optOff + 64;
  const securityIndex =
    securityDir != null ? securityDir.index ?? 4 : core.dataDirs.find(d => d.name === "SECURITY")?.index;
  const securityEntryOff =
    securityIndex == null ? checksumOff + 4 : core.optOff + core.ddStartRel + securityIndex * 8;
  const certOff = securityDir?.rva ?? 0;
  const certEnd = certOff + (securityDir?.size ?? 0);
  if (checksumOff >= reader.size) return null;

  const ranges: FileByteRange[] = [];
  const afterSecurityEntry = securityIndex == null ? securityEntryOff : securityEntryOff + 8;
  pushRange(ranges, reader, 0, checksumOff);
  pushRange(ranges, reader, checksumOff + 4, securityEntryOff);
  pushRange(ranges, reader, afterSecurityEntry, certOff);
  pushRange(ranges, reader, certEnd > afterSecurityEntry ? certEnd : afterSecurityEntry, reader.size);

  const data = await readRanges(reader, ranges);
  const digest = digestFunction ?? computeDigest;
  return bufferToHex(await digest(algorithm, data));
};

export const computePeAuthenticodeDigestFromParsedPe = async (
  reader: FileRangeReader,
  core: PeAuthenticodeParsedCore,
  securityDir: PeDataDirectory | undefined,
  algorithm: AlgorithmIdentifier,
  digestFunction?: DigestFunction
): Promise<string | null> => {
  const checksumOff = core.optOff + 64;
  const securityIndex = securityDir?.index ?? core.dataDirs.find(d => d.name === "SECURITY")?.index;
  const securityEntryOff =
    securityIndex == null ? checksumOff + 4 : core.optOff + core.ddStartRel + securityIndex * 8;
  const certOff = securityDir?.rva ?? 0;
  const certEnd = certOff + (securityDir?.size ?? 0);
  if (checksumOff >= reader.size) return null;

  const ranges: FileByteRange[] = [];
  const afterSecurityEntry = securityIndex == null ? securityEntryOff : securityEntryOff + 8;
  const sectionHashRegions = listSectionHashRegions(reader.size, core.sections);
  const headerHashEnd = computeHeaderHashEnd(
    reader.size,
    core.opt.SizeOfHeaders,
    afterSecurityEntry,
    core.sections
  );
  pushRange(ranges, reader, 0, checksumOff);
  pushRange(ranges, reader, checksumOff + 4, securityEntryOff);
  pushRangeExcludingRange(ranges, reader, afterSecurityEntry, headerHashEnd, certOff, certEnd);
  sectionHashRegions.forEach(sectionRegion =>
    pushRangeExcludingRange(ranges, reader, sectionRegion.start, sectionRegion.end, certOff, certEnd)
  );
  const trailingStart = sectionHashRegions.reduce((maxEnd, region) => Math.max(maxEnd, region.end), headerHashEnd);
  pushRangeExcludingRange(ranges, reader, trailingStart, reader.size, certOff, certEnd);

  const data = await readRanges(reader, ranges);
  const digest = digestFunction ?? computeDigest;
  return bufferToHex(await digest(algorithm, data));
};

export const computePeAuthenticodeDigest = async (
  reader: FileRangeReader,
  core: PeAuthenticodeBestEffortCore | PeAuthenticodeParsedCore,
  securityDir: PeDataDirectory | undefined,
  algorithm: AlgorithmIdentifier,
  digestFunction?: DigestFunction
): Promise<string | null> =>
  hasParsedPeHashContext(core)
    ? computePeAuthenticodeDigestFromParsedPe(reader, core, securityDir, algorithm, digestFunction)
    : computePeAuthenticodeDigestBestEffort(reader, core, securityDir, algorithm, digestFunction);

export const verifyAuthenticodeFileDigest = async (
  reader: FileRangeReader,
  core: PeAuthenticodeBestEffortCore | PeAuthenticodeParsedCore,
  securityDir: PeDataDirectory | undefined,
  auth: AuthenticodeInfo,
  digestFunction?: DigestFunction,
  getComputedDigest?: DigestLookup
): Promise<{ computedFileDigest?: string; fileDigestMatches?: boolean; warnings?: string[] }> => {
  const warnings: string[] = [];
  if (!auth.fileDigest) {
    warnings.push("Signature payload does not include a file digest.");
    return { warnings };
  }
  const algorithm = resolveAuthenticodeHash(auth);
  if (!algorithm) {
    warnings.push("Unsupported or unknown digest algorithm for verification.");
    return { warnings };
  }
  try {
    const computed = getComputedDigest
      ? await getComputedDigest(algorithm)
      : await computePeAuthenticodeDigest(reader, core, securityDir, algorithm, digestFunction);
    if (!computed) {
      warnings.push("Unable to compute Authenticode digest for this file.");
      return { warnings };
    }
    return {
      computedFileDigest: computed,
      fileDigestMatches: computed.toLowerCase() === auth.fileDigest.toLowerCase()
    };
  } catch (error) {
    warnings.push(`Digest verification failed: ${String(error)}`);
    return { warnings };
  }
};
