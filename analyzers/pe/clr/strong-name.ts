"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import type { PeClrHeader } from "./types.js";
import type { PeClrStrongName } from "./strong-name-types.js";
import { verifyStrongNameSignature } from "./strong-name-verification.js";

const toHexByte = (value: number): string => value.toString(16).padStart(2, "0");

export const formatPublicKeyToken = async (publicKey: number[] | undefined): Promise<string | null> => {
  if (!publicKey?.length || !globalThis.crypto?.subtle) return null;
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-1", new Uint8Array(publicKey)));
  // Strong-name public key tokens are the low 8 bytes of SHA-1(public key), shown in reverse order:
  // https://learn.microsoft.com/en-us/dotnet/standard/assembly/strong-named
  return Array.from(digest.slice(-8)).reverse().map(toHexByte).join("");
};

const isAllZero = (bytes: Uint8Array): boolean => bytes.every(byte => byte === 0);

const readSignature = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  rva: number,
  size: number,
  issues: string[]
): Promise<{ bytes: Uint8Array | null; offset: number | null; status: PeClrStrongName["status"] }> => {
  if (rva === 0 && size === 0) return { bytes: null, offset: null, status: "absent" };
  const offset = rvaToOff(rva);
  if (offset == null || offset < 0 || offset >= reader.size) {
    return { bytes: null, offset: null, status: "unmapped" };
  }
  const bytes = await reader.readBytes(offset, size);
  if (bytes.length < size) {
    issues.push("StrongNameSignature extends past end of file.");
    return { bytes, offset, status: "truncated" };
  }
  return { bytes, offset, status: isAllZero(bytes) ? "delay-signed" : "present" };
};

const verificationNote = (
  status: PeClrStrongName["status"],
  verified: boolean | null
): string => {
  if (status === "absent") return "No StrongNameSignature directory is present.";
  if (status === "delay-signed") {
    return "Signature bytes are all zero, which is typical for delay-signed assemblies.";
  }
  if (verified === true) return "RSA strong-name signature matches the locally computed strong-name hash.";
  if (verified === false) {
    return "RSA strong-name signature does not match the locally computed strong-name hash.";
  }
  return "Strong-name verification is unknown for this file/key shape.";
};

const verificationStatus = (verified: boolean | null): PeClrStrongName["verification"] =>
  verified == null ? "unknown" : verified ? "valid" : "invalid";

export const parseStrongName = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  clr: PeClrHeader
): Promise<PeClrStrongName> => {
  const issues: string[] = [];
  const publicKey = clr.meta?.tables?.assembly?.publicKey;
  const signature = await readSignature(
    reader,
    rvaToOff,
    clr.StrongNameSignatureRVA,
    clr.StrongNameSignatureSize,
    issues
  );
  const publicKeyToken = await formatPublicKeyToken(publicKey);
  const verified = signature.status === "present" && signature.bytes && signature.offset != null
    ? await verifyStrongNameSignature(
      reader,
      publicKey,
      signature.bytes,
      signature.offset,
      clr.meta?.tables?.assembly?.hashAlgorithm ?? 0,
      issues
    )
    : null;
  return {
    status: signature.status,
    publicKeyToken,
    verification: verificationStatus(verified),
    verificationNote: verificationNote(signature.status, verified),
    issues
  };
};
