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
  // PE Optional Header: CheckSum is at +64; Certificate Table is directory slot 4 (8 bytes).
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  // Hash physical file ranges, including gaps, as verified against the Windows PE SIP:
  // https://learn.microsoft.com/en-us/windows/win32/api/mssip/nf-mssip-cryptsipcreateindirectdata
  // Reconstructing the image from sections skips signed bytes and can hash overlaps twice.
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
): Promise<string | null> =>
  computePeAuthenticodeDigestBestEffort(reader, core, securityDir, algorithm, digestFunction);

export const computePeAuthenticodeDigest = async (
  reader: FileRangeReader,
  core: PeAuthenticodeBestEffortCore | PeAuthenticodeParsedCore,
  securityDir: PeDataDirectory | undefined,
  algorithm: AlgorithmIdentifier,
  digestFunction?: DigestFunction
): Promise<string | null> =>
  computePeAuthenticodeDigestBestEffort(reader, core, securityDir, algorithm, digestFunction);

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
