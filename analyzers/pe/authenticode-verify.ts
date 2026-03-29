"use strict";

import { bufferToHex } from "../../binary-utils.js";
import type { AuthenticodeInfo } from "./authenticode.js";
import type { PeCore, PeDataDirectory, PeSection, PeWindowsOptionalHeader } from "./types.js";

type DigestFunction = (algorithm: AlgorithmIdentifier, data: ArrayBuffer) => Promise<ArrayBuffer>;
export type PeAuthenticodeBestEffortCore = Pick<PeCore, "optOff" | "ddStartRel" | "dataDirs">;
export type PeAuthenticodeParsedCore = PeAuthenticodeBestEffortCore & {
  opt: Pick<PeWindowsOptionalHeader, "SizeOfHeaders">;
  sections: PeSection[];
};

const WEB_CRYPTO_HASHES: Record<string, AlgorithmIdentifier> = {
  sha1: "SHA-1",
  sha224: "SHA-224",
  sha256: "SHA-256",
  sha384: "SHA-384",
  sha512: "SHA-512"
};

const normalizeAlgName = (name: string): string =>
  name.toLowerCase().replace(/[^a-z0-9]/g, "");

const resolveWebCryptoHash = (auth: AuthenticodeInfo): AlgorithmIdentifier | null => {
  const raw =
    auth.fileDigestAlgorithmName ||
    auth.fileDigestAlgorithm ||
    (auth.digestAlgorithms?.length === 1 ? auth.digestAlgorithms[0] : undefined);
  if (!raw) return null;
  const normalized = normalizeAlgName(raw);
  return WEB_CRYPTO_HASHES[normalized] || null;
};

const pushSlice = (parts: Blob[], file: File, start: number, end: number): void => {
  const safeStart = Math.max(0, Math.min(start, file.size));
  const safeEnd = Math.max(0, Math.min(end, file.size));
  if (safeEnd > safeStart) {
    parts.push(file.slice(safeStart, safeEnd));
  }
};

const pushSliceExcludingRange = (
  parts: Blob[],
  file: File,
  start: number,
  end: number,
  excludedStart: number,
  excludedEnd: number
): void => {
  const safeStart = Math.max(0, Math.min(start, file.size));
  const safeEnd = Math.max(0, Math.min(end, file.size));
  if (safeEnd <= safeStart) return;
  if (excludedEnd <= safeStart || excludedStart >= safeEnd) {
    pushSlice(parts, file, safeStart, safeEnd);
    return;
  }
  pushSlice(parts, file, safeStart, Math.max(safeStart, excludedStart));
  pushSlice(parts, file, Math.min(safeEnd, excludedEnd), safeEnd);
};

const compareSectionHashOrder = (left: PeSection, right: PeSection): number =>
  (left.virtualAddress >>> 0) - (right.virtualAddress >>> 0) ||
  (left.pointerToRawData >>> 0) - (right.pointerToRawData >>> 0);

const listSectionHashRegions = (fileSize: number, sections: PeSection[]): Array<{ start: number; end: number }> =>
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

export const computePeAuthenticodeDigestBestEffort = async (
  file: File,
  core: PeAuthenticodeBestEffortCore,
  securityDir: PeDataDirectory | undefined,
  algorithm: AlgorithmIdentifier,
  digestFunction?: DigestFunction
): Promise<string | null> => {
  const checksumOff = core.optOff + 64;
  const securityIndex =
    securityDir != null
      ? securityDir.index ?? 4
      : core.dataDirs.find(d => d.name === "SECURITY")?.index;
  const securityEntryOff =
    securityIndex == null
      ? checksumOff + 4
      : core.optOff + core.ddStartRel + securityIndex * 8;
  const certOff = securityDir?.rva ?? 0;
  const certSize = securityDir?.size ?? 0;
  const certEnd = certOff + certSize;

  if (checksumOff >= file.size) return null;

  const parts: Blob[] = [];
  const afterSecurityEntry = securityIndex == null ? securityEntryOff : securityEntryOff + 8;
  pushSlice(parts, file, 0, checksumOff);
  pushSlice(parts, file, checksumOff + 4, securityEntryOff);
  pushSlice(parts, file, afterSecurityEntry, certOff);
  const tailStart = certEnd > afterSecurityEntry ? certEnd : afterSecurityEntry;
  pushSlice(parts, file, tailStart, file.size);

  const data = await new Blob(parts).arrayBuffer();
  const digest = digestFunction ?? ((a: AlgorithmIdentifier, d: ArrayBuffer) => crypto.subtle.digest(a, d));
  const digestBuffer = await digest(algorithm, data);
  return bufferToHex(digestBuffer);
};

export const computePeAuthenticodeDigestFromParsedPe = async (
  file: File,
  core: PeAuthenticodeParsedCore,
  securityDir: PeDataDirectory | undefined,
  algorithm: AlgorithmIdentifier,
  digestFunction?: DigestFunction
): Promise<string | null> => {
  const checksumOff = core.optOff + 64;
  const securityIndex = securityDir?.index ?? core.dataDirs.find(d => d.name === "SECURITY")?.index;
  const securityEntryOff =
    securityIndex == null
      ? checksumOff + 4
      : core.optOff + core.ddStartRel + securityIndex * 8;
  const certOff = securityDir?.rva ?? 0;
  const certSize = securityDir?.size ?? 0;
  const certEnd = certOff + certSize;

  if (checksumOff >= file.size) return null;

  const parts: Blob[] = [];
  const afterSecurityEntry = securityIndex == null ? securityEntryOff : securityEntryOff + 8;
  const headerHashEnd = computeHeaderHashEnd(file.size, core.opt.SizeOfHeaders, afterSecurityEntry, core.sections);
  pushSlice(parts, file, 0, checksumOff);
  pushSlice(parts, file, checksumOff + 4, securityEntryOff);
  pushSliceExcludingRange(parts, file, afterSecurityEntry, headerHashEnd, certOff, certEnd);
  for (const sectionRegion of listSectionHashRegions(file.size, core.sections)) {
    pushSliceExcludingRange(parts, file, sectionRegion.start, sectionRegion.end, certOff, certEnd);
  }

  const data = await new Blob(parts).arrayBuffer();
  const digest = digestFunction ?? ((a: AlgorithmIdentifier, d: ArrayBuffer) => crypto.subtle.digest(a, d));
  const digestBuffer = await digest(algorithm, data);
  return bufferToHex(digestBuffer);
};

export const computePeAuthenticodeDigest = async (
  file: File,
  core: PeAuthenticodeBestEffortCore | PeAuthenticodeParsedCore,
  securityDir: PeDataDirectory | undefined,
  algorithm: AlgorithmIdentifier,
  digestFunction?: DigestFunction
): Promise<string | null> =>
  hasParsedPeHashContext(core)
    ? computePeAuthenticodeDigestFromParsedPe(file, core, securityDir, algorithm, digestFunction)
    : computePeAuthenticodeDigestBestEffort(file, core, securityDir, algorithm, digestFunction);

export const verifyAuthenticodeFileDigest = async (
  file: File,
  core: PeAuthenticodeBestEffortCore | PeAuthenticodeParsedCore,
  securityDir: PeDataDirectory | undefined,
  auth: AuthenticodeInfo,
  digestFunction?: DigestFunction
): Promise<{ computedFileDigest?: string; fileDigestMatches?: boolean; warnings?: string[] }> => {
  const warnings: string[] = [];
  if (!auth.fileDigest) {
    warnings.push("Signature payload does not include a file digest.");
    return { warnings };
  }
  const algo = resolveWebCryptoHash(auth);
  if (!algo) {
    warnings.push("Unsupported or unknown digest algorithm for verification.");
    return { warnings };
  }
  try {
    const computed = await computePeAuthenticodeDigest(file, core, securityDir, algo, digestFunction);
    if (!computed) {
      warnings.push("Unable to compute Authenticode digest for this file.");
      return { warnings };
    }
    const fileDigestMatches = computed.toLowerCase() === auth.fileDigest.toLowerCase();
    return { computedFileDigest: computed, fileDigestMatches };
  } catch (error) {
    warnings.push(`Digest verification failed: ${String(error)}`);
    return { warnings };
  }
};
