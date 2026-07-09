"use strict";

import { toAsciiPrefix } from "../probes/text-heuristics.js";
import type { ProbeResult } from "../probes/probe-types.js";

// Linux initramfs buffer format is based on newc/crc CPIO. It defines a
// 6-byte ASCII magic string followed by thirteen 8-hex-digit header fields.
// https://docs.kernel.org/driver-api/early-userspace/buffer-format.html
const CPIO_NEWC_MAGIC = "070701";
const CPIO_CRC_MAGIC = "070702";
const CPIO_MAGIC_BYTE_LENGTH = CPIO_NEWC_MAGIC.length;
const CPIO_HEADER_FIELD_HEX_DIGITS = 8;
const CPIO_HEADER_FIELD_COUNT = 13;
const CPIO_FIXED_HEADER_BYTE_LENGTH =
  CPIO_MAGIC_BYTE_LENGTH + CPIO_HEADER_FIELD_COUNT * CPIO_HEADER_FIELD_HEX_DIGITS;

const isAsciiHexDigit = (byte: number): boolean =>
  /^[0-9A-Fa-f]$/.test(String.fromCharCode(byte));

const hasCpioFixedHeaderFields = (view: DataView): boolean => {
  if (view.byteLength < CPIO_FIXED_HEADER_BYTE_LENGTH) return false;
  for (let offset = CPIO_MAGIC_BYTE_LENGTH; offset < CPIO_FIXED_HEADER_BYTE_LENGTH; offset += 1) {
    if (!isAsciiHexDigit(view.getUint8(offset))) return false;
  }
  return true;
};

const detectCpioHeader = (view: DataView): ProbeResult => {
  if (!hasCpioFixedHeaderFields(view)) return null;
  const magic = toAsciiPrefix(view, CPIO_MAGIC_BYTE_LENGTH);
  if (magic === CPIO_NEWC_MAGIC) return "Linux initramfs (CPIO newc archive)";
  if (magic === CPIO_CRC_MAGIC) return "Linux initramfs (CPIO crc archive)";
  return null;
};

export { detectCpioHeader };
