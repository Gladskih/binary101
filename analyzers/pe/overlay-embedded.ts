"use strict";

import { probeElf } from "../elf/probe.js";
import { probeMachO } from "../macho/probe.js";
import { probeByMagic } from "../probes.js";

const DOS_SIGNATURE_MZ = 0x5a4d;
const DOS_E_LFANEW_OFFSET = 0x3c;
const PE_SIGNATURE = 0x50450000;
const NE_SIGNATURE = 0x4e45;
const LE_SIGNATURE = 0x4c45;
const LX_SIGNATURE = 0x4c58;
// RFC 1952 gzip header: ID1 ID2 CM FLG MTIME XFL OS; CM=8 is deflate and FLG bits 5-7 reserved.
// https://www.rfc-editor.org/rfc/rfc1952#section-2.3.1
const GZIP_SIGNATURE = 0x1f8b;
const GZIP_DEFLATE_METHOD = 8;
const GZIP_RESERVED_FLAGS_MASK = 0xe0;
export const EMBEDDED_EXECUTABLE_LABEL = "PE/NE/LX executable";

const hasExecutableMzSignature = (view: DataView): boolean => {
  if (view.byteLength < 0x40 || view.getUint16(0, true) !== DOS_SIGNATURE_MZ) return false;
  const headerOffset = view.getUint32(DOS_E_LFANEW_OFFSET, true);
  if (headerOffset <= 0 || headerOffset + 2 > view.byteLength) return false;
  const signature = view.getUint16(headerOffset, false);
  if (signature === NE_SIGNATURE || signature === LE_SIGNATURE || signature === LX_SIGNATURE) return true;
  return headerOffset + 4 <= view.byteLength && view.getUint32(headerOffset, false) === PE_SIGNATURE;
};

const hasValidGzipHeader = (view: DataView): boolean =>
  view.byteLength >= 10 &&
  view.getUint16(0, false) === GZIP_SIGNATURE &&
  view.getUint8(2) === GZIP_DEFLATE_METHOD &&
  (view.getUint8(3) & GZIP_RESERVED_FLAGS_MASK) === 0;

export const isEmbeddedCandidateStartByte = (byteValue: number): boolean =>
  byteValue === 0x04 ||
  byteValue === 0x1f ||
  byteValue === 0x25 ||
  byteValue === 0x28 ||
  byteValue === 0x37 ||
  byteValue === 0x42 ||
  byteValue === 0x47 ||
  byteValue === 0x4d ||
  byteValue === 0x50 ||
  byteValue === 0x52 ||
  byteValue === 0x7f ||
  byteValue === 0x89 ||
  byteValue === 0xca ||
  byteValue === 0xce ||
  byteValue === 0xcf ||
  byteValue === 0xd0 ||
  byteValue === 0xfd ||
  byteValue === 0xfe;

export const detectEmbeddedCandidateType = (
  view: DataView,
  remainingBytes: number
): string | null => {
  if (!view.byteLength || !isEmbeddedCandidateStartByte(view.getUint8(0))) return null;
  if (hasValidGzipHeader(view)) return "gzip compressed data";
  const label = probeByMagic(view) || probeElf(view) || probeMachO(view, remainingBytes);
  if (label && label !== "gzip compressed data") return label;
  return hasExecutableMzSignature(view) ? EMBEDDED_EXECUTABLE_LABEL : null;
};
