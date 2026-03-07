"use strict";

// Code-signing blob layouts come from xnu/osfmk/kern/cs_blobs.h:
// https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h

import {
  CSMAGIC_CODEDIRECTORY,
  CSMAGIC_EMBEDDED_SIGNATURE
} from "../../analyzers/macho/commands.js";

const textEncoder = new TextEncoder();

export const buildCodeSignature = (identifier: string, teamId: string): Uint8Array => {
  const identifierBytes = textEncoder.encode(identifier + "\0");
  const teamBytes = textEncoder.encode(teamId + "\0");
  // CS_CodeDirectory up to execSegFlags is 88 bytes in version 0x20400.
  const codeDirectoryLength = 88 + identifierBytes.length + teamBytes.length + 32;
  const codeDirectory = new Uint8Array(codeDirectoryLength);
  const codeView = new DataView(codeDirectory.buffer);
  const hashOffset = 88 + identifierBytes.length + teamBytes.length;
  codeView.setUint32(0, CSMAGIC_CODEDIRECTORY, false);
  codeView.setUint32(4, codeDirectoryLength, false);
  codeView.setUint32(8, 0x00020400, false); // CodeDirectory version with exec-segment fields.
  codeView.setUint32(12, 0x00010002, false); // CS_RUNTIME | CS_ADHOC.
  codeView.setUint32(16, hashOffset, false);
  codeView.setUint32(20, 88, false); // Identifier string starts immediately after the fixed header.
  codeView.setUint32(24, 0, false);
  codeView.setUint32(28, 1, false);
  codeView.setUint32(32, 0x400, false); // codeLimit
  codeDirectory[36] = 32; // SHA-256 digest length
  codeDirectory[37] = 2; // CS_HASHTYPE_SHA256
  codeDirectory[38] = 1; // PLATFORM_MACOS
  codeDirectory[39] = 12; // pageSize = 1 << 12
  codeView.setUint32(44, 0, false);
  codeView.setUint32(48, 88 + identifierBytes.length, false);
  codeView.setUint32(52, 0, false);
  codeView.setBigUint64(56, 0x400n, false);
  codeView.setBigUint64(64, 0n, false);
  codeView.setBigUint64(72, 0x300n, false);
  codeView.setBigUint64(80, 0x1n, false);
  codeDirectory.set(identifierBytes, 88);
  codeDirectory.set(teamBytes, 88 + identifierBytes.length);

  const superBlobLength = 20 + codeDirectory.length;
  const superBlob = new Uint8Array(superBlobLength);
  const superView = new DataView(superBlob.buffer);
  superView.setUint32(0, CSMAGIC_EMBEDDED_SIGNATURE, false);
  superView.setUint32(4, superBlobLength, false);
  superView.setUint32(8, 1, false);
  superView.setUint32(12, 0, false); // CSSLOT_CODEDIRECTORY
  superView.setUint32(16, 20, false); // Blob begins immediately after the one-entry index table.
  superBlob.set(codeDirectory, 20);
  return superBlob;
};
