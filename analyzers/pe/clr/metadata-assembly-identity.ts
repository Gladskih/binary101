"use strict";

import { sha1 } from "@noble/hashes/legacy.js";
import type { PeClrAssemblyInfo, PeClrAssemblyRefInfo } from "./types.js";

export interface ClrAssemblyIdentity {
  name: string;
  version: string;
  culture: string;
  publicKeyToken: string;
  contentType: number;
  processorArchitecture: number;
}

const identities = new WeakMap<PeClrAssemblyInfo | PeClrAssemblyRefInfo, ClrAssemblyIdentity | null>();
const hexBytes = (bytes: number[] | Uint8Array): string =>
  Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");

const validKeyBytes = (bytes: number[]): boolean =>
  bytes.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255);

const fullKeyToken = (bytes: number[]): string | null => {
  if (!validKeyBytes(bytes)) return null;
  // Strong-name tokens: reversed last eight bytes of SHA-1 of the full public key.
  // https://learn.microsoft.com/en-us/dotnet/standard/assembly/strong-named
  return bytes.length ? hexBytes(sha1(new Uint8Array(bytes)).slice(-8).reverse()) : "";
};

const referenceToken = (reference: PeClrAssemblyRefInfo): string | null => {
  const key = reference.publicKeyOrToken;
  if (!key || !validKeyBytes(key)) return null;
  // ECMA-335 II.22.5: AssemblyRef.PublicKey selects a full key rather than an eight-byte token.
  if (reference.flags & 1) return fullKeyToken(key);
  return key.length === 0 || key.length === 8 ? hexBytes(key) : null;
};

export const getClrAssemblyIdentity = (
  assembly: PeClrAssemblyInfo | PeClrAssemblyRefInfo | null
): ClrAssemblyIdentity | null => {
  if (!assembly) return null;
  if (identities.has(assembly)) return identities.get(assembly)!;
  const identity = readIdentity(assembly);
  identities.set(assembly, identity);
  return identity;
};

const readIdentity = (assembly: PeClrAssemblyInfo | PeClrAssemblyRefInfo): ClrAssemblyIdentity | null => {
  if (!assembly.name || assembly.culture == null) return null;
  // Heap index zero decodes to an empty value; absent values indicate a failed heap read.
  const token = "publicKeyOrToken" in assembly ? referenceToken(assembly)
    : assembly.publicKey ? fullKeyToken(assembly.publicKey) : null;
  if (token == null) return null;
  return { name: assembly.name.toLowerCase(), version: assembly.version,
    culture: assembly.culture.toLowerCase(),
    publicKeyToken: token,
    // Runtime AssemblyName.ContentType stores bits 9..11; ProcessorArchitecture stores bits 4..6.
    // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Reflection/AssemblyName.cs
    contentType: assembly.flags & 0x0e00,
    processorArchitecture: (assembly.flags & 0x70) >>> 4 };
};

export const clrAssemblyIdentityKey = (identity: ClrAssemblyIdentity): string =>
  JSON.stringify([identity.name, identity.version, identity.culture, identity.publicKeyToken,
    identity.contentType, identity.processorArchitecture]);
