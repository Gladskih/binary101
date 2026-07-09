"use strict";

import { hex } from "../../binary-utils.js";

export type LinuxBootHeaderWarnings = string[];

// Read through kernel_info offset (0x268) plus its u32 pointer field.
export const LINUX_BOOT_HEADER_READ_BYTES = 0x26c;
// Linux/x86 Boot Protocol stores setup-header-relative string pointers from
// the 0x200 real-mode header base.
// https://docs.kernel.org/arch/x86/boot.html#the-real-mode-kernel-header
export const REAL_MODE_HEADER_BASE_OFFSET = 0x200;
// Linux/x86 Boot Protocol, "The Real-Mode Kernel Header", defines these
// fixed real-mode setup-header byte offsets.
// https://docs.kernel.org/arch/x86/boot.html#the-real-mode-kernel-header
export const SETUP_SECTS_OFFSET = 0x1f1;
export const BOOT_FLAG_OFFSET = 0x1fe;
export const LINUX_MAGIC_OFFSET = 0x202;
export const VERSION_OFFSET = 0x206;
export const KERNEL_VERSION_OFFSET = 0x20e;
export const LOAD_FLAGS_OFFSET = 0x211;
export const KERNEL_ALIGNMENT_OFFSET = 0x230;
export const RELOCATABLE_KERNEL_OFFSET = 0x234;
export const XLOADFLAGS_OFFSET = 0x236;
export const CMDLINE_SIZE_OFFSET = 0x238;
export const PAYLOAD_OFFSET = 0x248;
export const PAYLOAD_LENGTH_OFFSET = 0x24c;
export const PREFERRED_ADDRESS_OFFSET = 0x258;
export const INIT_SIZE_OFFSET = 0x260;
export const HANDOVER_OFFSET = 0x264;
export const KERNEL_INFO_OFFSET = 0x268;
// Linux/x86 Boot Protocol: modern fields below are only valid from the
// documented protocol version that introduced them.
// https://docs.kernel.org/arch/x86/boot.html#details-of-header-fields
export const PROTOCOL_RELOCATABLE_KERNEL = 0x0205;
export const PROTOCOL_CMDLINE_SIZE = 0x0206;
export const PROTOCOL_PAYLOAD = 0x0208;
export const PROTOCOL_INIT_SIZE = 0x020a;
export const PROTOCOL_HANDOVER_OFFSET = 0x020b;
export const PROTOCOL_XLOADFLAGS = 0x020c;
export const PROTOCOL_KERNEL_INFO = 0x020f;
export const BOOT_FLAG_MAGIC = 0xaa55;
export const LINUX_MAGIC = "HdrS";
// Linux/x86 Boot Protocol: setup_sects value 0 means 4 for backwards compatibility.
export const DEFAULT_SETUP_SECTORS = 4;
export const SECTOR_BYTES = 512;

type HeaderValueReader<Value> = () => Value;

const warnTruncatedHeaderField = (
  warnings: LinuxBootHeaderWarnings,
  fieldName: string,
  offset: number,
  byteLength: number,
  headerByteLength: number
): void => {
  warnings.push(
    `Linux boot header field ${fieldName} at ${hex(offset, 4)} is truncated ` +
    `(${byteLength} byte(s) required, header has ${headerByteLength} byte(s)).`
  );
};

const readHeaderValue = <Value>(
  view: DataView,
  warnings: LinuxBootHeaderWarnings,
  fieldName: string,
  offset: number,
  byteLength: number,
  readValue: HeaderValueReader<Value>
): Value | null => {
  if (offset >= 0 && offset + byteLength <= view.byteLength) return readValue();
  warnTruncatedHeaderField(warnings, fieldName, offset, byteLength, view.byteLength);
  return null;
};

export const readLinuxBootHeaderUint8 = (
  view: DataView,
  warnings: LinuxBootHeaderWarnings,
  fieldName: string,
  offset: number
): number | null =>
  readHeaderValue(view, warnings, fieldName, offset, Uint8Array.BYTES_PER_ELEMENT, () =>
    view.getUint8(offset)
  );

export const readLinuxBootHeaderUint16 = (
  view: DataView,
  warnings: LinuxBootHeaderWarnings,
  fieldName: string,
  offset: number
): number | null =>
  readHeaderValue(view, warnings, fieldName, offset, Uint16Array.BYTES_PER_ELEMENT, () =>
    view.getUint16(offset, true)
  );

export const readLinuxBootHeaderUint32 = (
  view: DataView,
  warnings: LinuxBootHeaderWarnings,
  fieldName: string,
  offset: number
): number | null =>
  readHeaderValue(view, warnings, fieldName, offset, Uint32Array.BYTES_PER_ELEMENT, () =>
    view.getUint32(offset, true)
  );

export const readLinuxBootHeaderUint64 = (
  view: DataView,
  warnings: LinuxBootHeaderWarnings,
  fieldName: string,
  offset: number
): bigint | null =>
  readHeaderValue(view, warnings, fieldName, offset, BigUint64Array.BYTES_PER_ELEMENT, () =>
    view.getBigUint64(offset, true)
  );
