"use strict";

import { bufferToHex } from "../../binary-utils.js";
import type { AuthenticodeInfo } from "./authenticode.js";
import type { PeCore, PeDataDirectory } from "./types.js";

type DigestFunction = (algorithm: AlgorithmIdentifier, data: ArrayBuffer) => Promise<ArrayBuffer>;

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
  const raw = auth.fileDigestAlgorithmName || auth.fileDigestAlgorithm || auth.digestAlgorithms?.[0];
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

export const computePeAuthenticodeDigest = async (
  file: File,
  core: Pick<PeCore, "optOff" | "ddStartRel" | "dataDirs">,
  securityDir: PeDataDirectory | undefined,
  algorithm: AlgorithmIdentifier,
  digestFunction?: DigestFunction
): Promise<string | null> => {
  const checksumOff = core.optOff + 64;
  const securityIndex = securityDir?.index ?? core.dataDirs.find(d => d.name === "SECURITY")?.index ?? 4;
  const securityEntryOff = core.optOff + core.ddStartRel + securityIndex * 8;
  const certOff = securityDir?.rva ?? 0;
  const certSize = securityDir?.size ?? 0;
  const certEnd = certOff + certSize;

  if (checksumOff >= file.size) return null;

  const parts: Blob[] = [];
  const afterSecurityEntry = securityEntryOff + 8;
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

export const verifyAuthenticodeFileDigest = async (
  file: File,
  core: Pick<PeCore, "optOff" | "ddStartRel" | "dataDirs">,
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
