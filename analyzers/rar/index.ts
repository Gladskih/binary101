"use strict";

import { SIGNATURE_V5 } from "./constants.js";
import { detectRarVersionBytes } from "./utils.js";
import { parseRar4 } from "./rar4.js";
import { parseRar5 } from "./rar5.js";

export { hasRarSignature } from "./utils.js";

export interface RarMainHeader {
  isVolume?: boolean;
  isSolid?: boolean;
  hasRecovery?: boolean;
  hasComment?: boolean;
  isLocked?: boolean;
  isEncrypted?: boolean;
  isFirstVolume?: boolean;
  volumeNumber?: number | null;
}

export interface RarEntry {
  index?: number;
  name?: string;
  packSize?: bigint | number | null;
  unpackedSize?: bigint | number | null;
  hostOs?: string;
  crc32?: number | null;
  modified?: string | null;
  method?: string;
  isDirectory?: boolean;
  isSolid?: boolean;
  isEncrypted?: boolean;
  isSplitBefore?: boolean;
  isSplitAfter?: boolean;
  isInherited?: boolean;
  isChild?: boolean;
}

export interface RarEndHeader {
  offset: number;
  flags: number;
  nextVolume: boolean;
}

export interface RarParseResult {
  isRar: boolean;
  version: number | null;
  mainHeader: RarMainHeader | null;
  entries: RarEntry[];
  endHeader: RarEndHeader | null;
  issues: string[];
}

export async function parseRar(file: File): Promise<RarParseResult> {
  const signatureBytes = new Uint8Array(await file.slice(0, SIGNATURE_V5.length).arrayBuffer());
  const version = detectRarVersionBytes(signatureBytes);
  if (version === 4) return parseRar4(file) as unknown as RarParseResult;
  if (version === 5) return parseRar5(file) as unknown as RarParseResult;
  return {
    isRar: false,
    version: null,
    mainHeader: null,
    entries: [],
    endHeader: null,
    issues: ["Not a RAR archive."]
  };
}
