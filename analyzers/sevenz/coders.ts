"use strict";

export const CODER_NAMES: Record<string, string> = {
  "00": "Copy",
  "03": "Delta",
  "030101": "LZMA",
  "21": "LZMA2",
  "03030103": "BCJ",
  "0303011b": "BCJ2",
  "04": "BZip2",
  "040108": "Deflate",
  "030401": "PPMd",
  "06f10701": "AES-256"
};

export const CODER_ARCH_HINTS: Record<string, string> = {
  "03030103": "x86",
  "0303011b": "x86",
  "03030105": "IA-64",
  "03030106": "ARM",
  "03030107": "ARM-Thumb",
  "03030108": "PowerPC"
};

export const normalizeMethodId = (id: string | null | undefined): string =>
  (id || "").toString().toLowerCase();

export const describeCoderId = (id: string): string =>
  CODER_NAMES[normalizeMethodId(id)] || `0x${id}`;

const parseLzmaProps = (bytes: Uint8Array | null | undefined):
  | { dictSize: number; lc: number; lp: number; pb: number }
  | null => {
  if (!bytes || bytes.length < 5) return null;
  const [first, b1, b2, b3, b4] = bytes;
  if (
    first === undefined ||
    b1 === undefined ||
    b2 === undefined ||
    b3 === undefined ||
    b4 === undefined
  ) {
    return null;
  }
  const pb = Math.floor(first / 45);
  const remainder = first - pb * 45;
  const lp = Math.floor(remainder / 9);
  const lc = remainder - lp * 9;
  const dictSize = b1 | (b2 << 8) | (b3 << 16) | (b4 << 24);
  return { dictSize, lc, lp, pb };
};

const parseLzma2Props = (bytes: Uint8Array | null | undefined): { dictSize: number | null } | null => {
  if (!bytes || bytes.length < 1) return null;
  const prop = bytes[0];
  if (prop === undefined) return null;
  if (prop > 40) return { dictSize: null };
  const base = (prop & 1) + 2;
  const dictSize = base << (Math.floor(prop / 2) + 11);
  return { dictSize };
};

const parseDeltaProps = (bytes: Uint8Array | null | undefined): { distance: number } | null => {
  if (!bytes || bytes.length < 1) return null;
  const first = bytes[0];
  if (first === undefined) return null;
  const distance = first + 1;
  return { distance };
};

const parseBcjProps = (
  id: string,
  bytes: Uint8Array | null | undefined
): { filterType?: string; startOffset?: number } | null => {
  const arch = CODER_ARCH_HINTS[normalizeMethodId(id)];
  if (!bytes || !bytes.length) return arch ? { filterType: arch } : null;
  if (bytes.length >= 4) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const startOffset = view.getInt32(0, true);
    return arch ? { filterType: arch, startOffset } : { startOffset };
  }
  return arch ? { filterType: arch } : null;
};

export const parseCoderProperties = (
  methodId: string,
  bytes: Uint8Array | null | undefined
): unknown => {
  const normalized = normalizeMethodId(methodId);
  if (normalized === "030101") return parseLzmaProps(bytes);
  if (normalized === "21") return parseLzma2Props(bytes);
  if (normalized === "03") return parseDeltaProps(bytes);
  if (normalized.startsWith("030301")) return parseBcjProps(methodId, bytes);
  return null;
};
