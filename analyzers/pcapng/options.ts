"use strict";

import { alignUpTo } from "../../binary-utils.js";

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: false });
const OPTION_HEADER_BYTES = 4;

// pcapng options are padded to a 32-bit boundary.
// Source: draft-ietf-opsawg-pcapng-05 Section 3.5 and Section 3.6.2,
// https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
const PCAPNG_ALIGNMENT_BYTES = 4;

export type PcapNgOption = {
  code: number;
  value: Uint8Array;
};

// uint64/sint64 pcapng option payloads occupy exactly 8 octets.
// Source: draft-ietf-opsawg-pcapng-05 Section 3.5 Table 1,
// https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
const readUint64FromBytes = (value: Uint8Array, littleEndian: boolean): bigint | null => {
  if (value.length !== 8) return null;
  const dv = new DataView(value.buffer, value.byteOffset, value.byteLength);
  return dv.getBigUint64(0, littleEndian);
};

const readInt64FromBytes = (value: Uint8Array, littleEndian: boolean): bigint | null => {
  if (value.length !== 8) return null;
  const dv = new DataView(value.buffer, value.byteOffset, value.byteLength);
  return dv.getBigInt64(0, littleEndian);
};

export const decodeUtf8 = (value: Uint8Array): string => UTF8_DECODER.decode(value);

export const parsePcapNgOptions = (
  dv: DataView,
  start: number,
  end: number,
  littleEndian: boolean,
  pushIssue: (message: string) => void,
  contextLabel: string
): PcapNgOption[] => {
  const options: PcapNgOption[] = [];
  let cursor = start;
  // Options are Type-Length-Value tuples with a 4-octet header, terminated by opt_endofopt=0.
  // Source: draft-ietf-opsawg-pcapng-05 Section 3.5 Table 1,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  while (cursor + OPTION_HEADER_BYTES <= end) {
    const code = dv.getUint16(cursor, littleEndian);
    const length = dv.getUint16(cursor + 2, littleEndian);
    cursor += OPTION_HEADER_BYTES;
    if (code === 0) return options; // opt_endofopt has code 0.
    const valueEnd = cursor + length;
    if (valueEnd > end) {
      pushIssue(`${contextLabel} option ${code} runs past the end of the block.`);
      return options;
    }
    options.push({
      code,
      value: new Uint8Array(dv.buffer, dv.byteOffset + cursor, length)
    });
    cursor += alignUpTo(length, PCAPNG_ALIGNMENT_BYTES);
  }
  if (cursor !== end) {
    pushIssue(`${contextLabel} options end with ${end - cursor} trailing bytes.`);
  }
  return options;
};

export const readUint64Option = (option: PcapNgOption, littleEndian: boolean): bigint | null =>
  readUint64FromBytes(option.value, littleEndian);

export const readInt64Option = (option: PcapNgOption, littleEndian: boolean): bigint | null =>
  readInt64FromBytes(option.value, littleEndian);

export const describeTimestampResolution = (value: Uint8Array | null): {
  unitsPerSecond: number;
  label: string;
} => {
  // if_tsresol uses the MSB to choose base-10 vs base-2; the remaining 7 bits are the exponent.
  // If the option is absent, 10^-6 seconds is the default.
  // Source: draft-ietf-opsawg-pcapng-05 Section 4.2,
  // https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
  const raw = value?.[0] ?? 6;
  const isBinary = (raw & 0x80) !== 0;
  const exponent = raw & 0x7f;
  const unitsPerSecond = isBinary ? 2 ** exponent : 10 ** exponent;
  if (Number.isFinite(unitsPerSecond) && unitsPerSecond > 0) {
    const label = isBinary ? `2^-${exponent} s` : `10^-${exponent} s`;
    return { unitsPerSecond, label };
  }
  return { unitsPerSecond: 1_000_000, label: "10^-6 s" };
};

export const readFilterOption = (option: PcapNgOption): string => {
  if (option.value.length === 0) return "";
  const filterType = option.value[0] ?? 0;
  // The current pcapng draft leaves concrete if_filter subtypes under-specified.
  // Wireshark's upstream pcapng documentation treats subtype 0 as a libpcap filter string.
  // Source: https://wiki.wireshark.org/Development/PcapNg
  if (filterType === 0) {
    return decodeUtf8(option.value.subarray(1));
  }
  return `Filter type ${filterType} (${Math.max(0, option.value.length - 1)} bytes)`;
};
