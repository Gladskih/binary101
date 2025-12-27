"use strict";

import type { TgaFooter } from "./types.js";
import { TGA_FOOTER_SIZE, decodeFixedString, readUint32le, readUint8 } from "./tga-parsing.js";

export const parseTgaFooter = async (file: File): Promise<TgaFooter | null> => {
  if (file.size < TGA_FOOTER_SIZE) return null;
  const bytes = new Uint8Array(await file.slice(file.size - TGA_FOOTER_SIZE, file.size).arrayBuffer());
  const truncated = bytes.length < TGA_FOOTER_SIZE;
  if (truncated) {
    return { present: false, extensionOffset: null, developerDirectoryOffset: null, signature: null, truncated };
  }

  const extensionOffset = readUint32le(bytes, 0);
  const developerDirectoryOffset = readUint32le(bytes, 4);
  const signatureCore = decodeFixedString(bytes, 8, 16);
  const dot = readUint8(bytes, 24);
  const nul = readUint8(bytes, 25);
  const present = signatureCore === "TRUEVISION-XFILE" && dot === 0x2e && nul === 0x00;
  const signature = present ? "TRUEVISION-XFILE.\\0" : signatureCore || null;
  return { present, extensionOffset, developerDirectoryOffset, signature, truncated };
};

export const hasTgaFooterSignature = async (file: File): Promise<boolean> => {
  const footer = await parseTgaFooter(file);
  return footer?.present === true;
};

