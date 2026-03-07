"use strict";

// Code-signing blob magics, slots, flags, and hash types are defined in
// xnu/osfmk/kern/cs_blobs.h:
// https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h

const codeSignatureMagicNames = new Map<number, string>([
  [0xfade0c00, "Requirement"],
  [0xfade0c01, "Requirements"],
  [0xfade0c02, "CodeDirectory"],
  [0xfade0cc0, "Embedded signature"],
  [0xfade0b02, "Embedded signature (old)"],
  [0xfade7171, "Embedded entitlements"],
  [0xfade7172, "Embedded DER entitlements"],
  [0xfade0cc1, "Detached signature"],
  [0xfade0b01, "Blob wrapper / CMS"]
]);

const codeSignatureSlotNames = new Map<number, string>([
  [0, "CodeDirectory"],
  [1, "Info.plist"],
  [2, "Requirements"],
  [3, "Resource directory"],
  [4, "Application-specific"],
  [5, "Entitlements"],
  [7, "DER entitlements"],
  [8, "Launch constraints (self)"],
  [9, "Launch constraints (parent)"],
  [10, "Launch constraints (responsible)"],
  [11, "Library constraints"],
  [0x10000, "CMS signature"],
  [0x10001, "Identification"],
  [0x10002, "Ticket"]
]);

const codeDirectoryFlagNames = new Map<number, string>([
  [0x00000002, "Ad hoc"],
  [0x00000100, "Hardened (CS_HARD)"],
  [0x00000200, "Kill on invalid pages"],
  [0x00000400, "Check expiration"],
  [0x00000800, "Restricted"],
  [0x00001000, "Enforcement"],
  [0x00002000, "Require library validation"],
  [0x00010000, "Hardened runtime"],
  [0x00020000, "Linker-signed"]
]);

const codeDirectoryExecSegFlagNames = new Map<bigint, string>([
  [0x1n, "Main binary"],
  [0x10n, "Allow unsigned"],
  [0x20n, "Debugger"],
  [0x40n, "JIT"],
  [0x80n, "Skip library validation"],
  [0x100n, "Can load blessed cdhash"],
  [0x200n, "Can execute blessed cdhash"]
]);

const codeDirectoryHashNames = new Map<number, string>([
  [1, "SHA-1"],
  [2, "SHA-256"],
  [3, "SHA-256 (truncated)"],
  [4, "SHA-384"]
]);

const collectFlagNames = (mask: number, names: Map<number, string>): string[] =>
  [...names.entries()]
    .filter(([bit]) => (mask & bit) !== 0)
    .map(([, name]) => name);

const collectBigIntFlagNames = (mask: bigint, names: Map<bigint, string>): string[] =>
  [...names.entries()]
    .filter(([bit]) => (mask & bit) !== 0n)
    .map(([, name]) => name);

const codeSignatureMagicName = (magic: number): string | null => codeSignatureMagicNames.get(magic) || null;
const codeSignatureSlotName = (type: number): string => codeSignatureSlotNames.get(type) || `0x${type.toString(16)}`;
const codeDirectoryFlagNamesFor = (flags: number): string[] => collectFlagNames(flags, codeDirectoryFlagNames);
const codeDirectoryExecSegFlags = (flags: bigint): string[] =>
  collectBigIntFlagNames(flags, codeDirectoryExecSegFlagNames);
const codeDirectoryHashName = (hashType: number): string | null => codeDirectoryHashNames.get(hashType) || null;

export {
  codeDirectoryExecSegFlags,
  codeDirectoryFlagNamesFor,
  codeDirectoryHashName,
  codeSignatureMagicName,
  codeSignatureSlotName
};
