"use strict";

import { isPrintableByte, readAsciiString } from "../../binary-utils.js";
import type { FileRangeReader } from "../file-range-reader.js";
import { parseGzip } from "../gzip/index.js";
import type { GzipParseResult } from "../gzip/types.js";
import { hasGzipDeflateHeaderBytes } from "../gzip/signature.js";
import {
  BOOT_FLAG_MAGIC,
  BOOT_FLAG_OFFSET,
  CMDLINE_SIZE_OFFSET,
  DEFAULT_SETUP_SECTORS,
  HANDOVER_OFFSET,
  INIT_SIZE_OFFSET,
  KERNEL_ALIGNMENT_OFFSET,
  KERNEL_INFO_OFFSET,
  KERNEL_VERSION_OFFSET,
  LINUX_BOOT_HEADER_READ_BYTES,
  LINUX_MAGIC,
  LINUX_MAGIC_OFFSET,
  LOAD_FLAGS_OFFSET,
  PAYLOAD_LENGTH_OFFSET,
  PAYLOAD_OFFSET,
  PREFERRED_ADDRESS_OFFSET,
  PROTOCOL_CMDLINE_SIZE,
  PROTOCOL_HANDOVER_OFFSET,
  PROTOCOL_INIT_SIZE,
  PROTOCOL_KERNEL_INFO,
  PROTOCOL_PAYLOAD,
  PROTOCOL_RELOCATABLE_KERNEL,
  PROTOCOL_XLOADFLAGS,
  REAL_MODE_HEADER_BASE_OFFSET,
  RELOCATABLE_KERNEL_OFFSET,
  SECTOR_BYTES,
  SETUP_SECTS_OFFSET,
  VERSION_OFFSET,
  XLOADFLAGS_OFFSET,
  readLinuxBootHeaderUint8,
  readLinuxBootHeaderUint16,
  readLinuxBootHeaderUint32,
  readLinuxBootHeaderUint64
} from "./linux-boot-header.js";

export interface PeLinuxBootPayload {
  offset: number;
  length: number;
  fileOffset: number;
  endOffset: number;
  format: "gzip" | "unknown";
  magicHex?: string;
  gzip?: GzipParseResult;
}

export interface PeLinuxKernelInfo {
  fileOffset: number;
  header: string;
  size: number;
  totalSize: number;
  setupTypeMax: number;
  warnings?: string[];
}

export interface PeLinuxBootProtocol {
  setupSectorsRaw: number;
  setupSectors: number;
  bootFlag: number;
  protocolVersion: number;
  kernelVersionOffset: number;
  kernelVersion?: string;
  loadFlags: number;
  xloadFlags?: number;
  kernelAlignment?: number;
  relocatableKernel?: boolean;
  cmdlineSize?: number;
  preferredAddress?: bigint;
  initSize?: number;
  handoverOffset?: number;
  kernelInfoOffset?: number;
  payload?: PeLinuxBootPayload;
  kernelInfo?: PeLinuxKernelInfo;
  warnings?: string[];
}

const KERNEL_INFO_BYTES = 16;
// Linux/x86 Boot Protocol kernel_info starts with "LToP", then three
// little-endian u32 fields: size, total_size, setup_type_max.
// https://docs.kernel.org/arch/x86/boot.html#kernel-info
const KERNEL_INFO_HEADER_BYTES = 4;
const KERNEL_INFO_SIZE_OFFSET = 4;
const KERNEL_INFO_TOTAL_SIZE_OFFSET = 8;
const KERNEL_INFO_SETUP_TYPE_MAX_OFFSET = 12;
// Bound unterminated kernel_version strings from malformed images to a small,
// human-readable metadata read.
const KERNEL_VERSION_READ_LIMIT_BYTES = 256;
// Diagnostic preview only; full gzip parsing uses the declared payload range.
const PAYLOAD_MAGIC_PREVIEW_BYTES = 4;

const readCString = async (
  reader: FileRangeReader,
  offset: number,
  maxLength: number
): Promise<string | undefined> => {
  if (offset < 0 || offset >= reader.size) return undefined;
  const bytes = await reader.readBytes(offset, Math.min(maxLength, reader.size - offset));
  let text = "";
  for (const byte of bytes) {
    if (byte === 0) return text || undefined;
    if (!isPrintableByte(byte)) return undefined;
    text += String.fromCharCode(byte);
  }
  return undefined;
};

const formatMagicHex = (bytes: Uint8Array): string | undefined =>
  bytes.length
    ? Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join(" ")
    : undefined;

const detectPayloadFormat = async (
  reader: FileRangeReader,
  fileOffset: number,
  endOffset: number,
  source?: Blob
): Promise<{ format: "gzip" | "unknown"; magicHex?: string; gzip?: GzipParseResult }> => {
  if (fileOffset < 0 || fileOffset >= reader.size) return { format: "unknown" };
  const bytes = await reader.readBytes(
    fileOffset,
    Math.min(PAYLOAD_MAGIC_PREVIEW_BYTES, reader.size - fileOffset)
  );
  const magicHex = formatMagicHex(bytes);
  const gzip = endOffset > fileOffset && source
    ? await parseGzip(source.slice(fileOffset, endOffset, "application/gzip"))
    : null;
  return {
    format: gzip || hasGzipDeflateHeaderBytes(bytes) ? "gzip" : "unknown",
    ...(magicHex ? { magicHex } : {}),
    ...(gzip ? { gzip } : {})
  };
};

const readKernelVersion = async (
  reader: FileRangeReader,
  setupSectors: number,
  versionOffset: number
): Promise<string | undefined> => {
  const maxSetupBytes = setupSectors * SECTOR_BYTES;
  if (!versionOffset || versionOffset >= maxSetupBytes) return undefined;
  return readCString(reader, REAL_MODE_HEADER_BASE_OFFSET + versionOffset, KERNEL_VERSION_READ_LIMIT_BYTES);
};

const buildPayload = async (
  reader: FileRangeReader,
  warnings: string[],
  protectedModeOffset: number,
  payloadOffset: number,
  payloadLength: number,
  source?: Blob
): Promise<PeLinuxBootPayload | undefined> => {
  if (!payloadLength) return undefined;
  const fileOffset = protectedModeOffset + payloadOffset;
  const endOffset = fileOffset + payloadLength;
  if (!Number.isSafeInteger(fileOffset) || !Number.isSafeInteger(endOffset)) {
    warnings.push("Linux payload range overflows JavaScript safe integer bounds.");
    return undefined;
  }
  if (fileOffset < 0 || endOffset > reader.size || endOffset <= fileOffset) {
    warnings.push("Linux payload range points outside the file.");
  }
  return {
    offset: payloadOffset,
    length: payloadLength,
    fileOffset,
    endOffset,
    ...(await detectPayloadFormat(reader, fileOffset, endOffset, source))
  };
};

const parseKernelInfo = async (
  reader: FileRangeReader,
  protectedModeOffset: number,
  kernelInfoOffset: number
): Promise<PeLinuxKernelInfo | undefined> => {
  if (!kernelInfoOffset) return undefined;
  const fileOffset = protectedModeOffset + kernelInfoOffset;
  if (!Number.isSafeInteger(fileOffset) || fileOffset < 0 || fileOffset + KERNEL_INFO_BYTES > reader.size) {
    return {
      fileOffset,
      header: "",
      size: 0,
      totalSize: 0,
      setupTypeMax: 0,
      warnings: ["Linux kernel_info range points outside the file."]
    };
  }
  const view = await reader.read(fileOffset, KERNEL_INFO_BYTES);
  if (view.byteLength < KERNEL_INFO_BYTES) {
    return {
      fileOffset,
      header: readAsciiString(view, 0, KERNEL_INFO_HEADER_BYTES),
      size: 0,
      totalSize: 0,
      setupTypeMax: 0,
      warnings: ["Linux kernel_info read returned fewer bytes than expected."]
    };
  }
  const warnings = readAsciiString(view, 0, KERNEL_INFO_HEADER_BYTES) === "LToP"
    ? []
    : ["Linux kernel_info magic is not LToP."];
  return {
    fileOffset,
    header: readAsciiString(view, 0, KERNEL_INFO_HEADER_BYTES),
    size: view.getUint32(KERNEL_INFO_SIZE_OFFSET, true),
    totalSize: view.getUint32(KERNEL_INFO_TOTAL_SIZE_OFFSET, true),
    setupTypeMax: view.getUint32(KERNEL_INFO_SETUP_TYPE_MAX_OFFSET, true),
    ...(warnings.length ? { warnings } : {})
  };
};

export const formatLinuxBootProtocolVersion = (version: number): string =>
  `${(version >> 8) & 0xff}.${(version & 0xff).toString().padStart(2, "0")}`;

export const parseLinuxBootProtocol = async (
  reader: FileRangeReader,
  source?: Blob
): Promise<PeLinuxBootProtocol | null> => {
  const header = await reader.read(0, Math.min(reader.size, LINUX_BOOT_HEADER_READ_BYTES));
  if (
    header.byteLength <= VERSION_OFFSET ||
    readAsciiString(header, LINUX_MAGIC_OFFSET, LINUX_MAGIC.length) !== LINUX_MAGIC
  ) {
    return null;
  }
  const warnings: string[] = [];
  const setupSectorsRaw = readLinuxBootHeaderUint8(header, warnings, "setup_sects", SETUP_SECTS_OFFSET) ?? 0;
  const setupSectors = setupSectorsRaw || DEFAULT_SETUP_SECTORS;
  const bootFlag = readLinuxBootHeaderUint16(header, warnings, "boot_flag", BOOT_FLAG_OFFSET) ?? 0;
  const protocolVersion = readLinuxBootHeaderUint16(header, warnings, "version", VERSION_OFFSET) ?? 0;
  const kernelVersionOffset = readLinuxBootHeaderUint16(
    header,
    warnings,
    "kernel_version",
    KERNEL_VERSION_OFFSET
  ) ?? 0;
  const kernelVersion = await readKernelVersion(reader, setupSectors, kernelVersionOffset);
  const protectedModeOffset = (setupSectors + 1) * SECTOR_BYTES;
  if (bootFlag !== BOOT_FLAG_MAGIC) warnings.push("Linux boot_flag is not 0xAA55.");
  const payload = protocolVersion >= PROTOCOL_PAYLOAD
    ? await buildPayload(
        reader,
        warnings,
        protectedModeOffset,
        readLinuxBootHeaderUint32(header, warnings, "payload_offset", PAYLOAD_OFFSET) ?? 0,
        readLinuxBootHeaderUint32(header, warnings, "payload_length", PAYLOAD_LENGTH_OFFSET) ?? 0,
        source
      )
    : undefined;
  const kernelInfoOffset = protocolVersion >= PROTOCOL_KERNEL_INFO
    ? readLinuxBootHeaderUint32(header, warnings, "kernel_info", KERNEL_INFO_OFFSET) ?? 0
    : undefined;
  const kernelInfo = kernelInfoOffset
    ? await parseKernelInfo(reader, protectedModeOffset, kernelInfoOffset)
    : undefined;
  return {
    setupSectorsRaw,
    setupSectors,
    bootFlag,
    protocolVersion,
    kernelVersionOffset,
    ...(kernelVersion ? { kernelVersion } : {}),
    loadFlags: readLinuxBootHeaderUint8(header, warnings, "loadflags", LOAD_FLAGS_OFFSET) ?? 0,
    ...(protocolVersion >= PROTOCOL_RELOCATABLE_KERNEL
      ? {
          kernelAlignment: readLinuxBootHeaderUint32(
            header,
            warnings,
            "kernel_alignment",
            KERNEL_ALIGNMENT_OFFSET
          ) ?? 0,
          relocatableKernel:
            (readLinuxBootHeaderUint8(header, warnings, "relocatable_kernel", RELOCATABLE_KERNEL_OFFSET) ?? 0) !== 0
        }
      : {}),
    ...(protocolVersion >= PROTOCOL_CMDLINE_SIZE
      ? { cmdlineSize: readLinuxBootHeaderUint32(header, warnings, "cmdline_size", CMDLINE_SIZE_OFFSET) ?? 0 }
      : {}),
    ...(protocolVersion >= PROTOCOL_XLOADFLAGS
      ? { xloadFlags: readLinuxBootHeaderUint16(header, warnings, "xloadflags", XLOADFLAGS_OFFSET) ?? 0 }
      : {}),
    ...(protocolVersion >= PROTOCOL_INIT_SIZE
      ? {
          preferredAddress:
            readLinuxBootHeaderUint64(header, warnings, "pref_address", PREFERRED_ADDRESS_OFFSET) ?? 0n,
          initSize: readLinuxBootHeaderUint32(header, warnings, "init_size", INIT_SIZE_OFFSET) ?? 0
        }
      : {}),
    ...(protocolVersion >= PROTOCOL_HANDOVER_OFFSET
      ? { handoverOffset: readLinuxBootHeaderUint32(header, warnings, "handover_offset", HANDOVER_OFFSET) ?? 0 }
      : {}),
    ...(kernelInfoOffset != null ? { kernelInfoOffset } : {}),
    ...(payload ? { payload } : {}),
    ...(kernelInfo ? { kernelInfo } : {}),
    ...(warnings.length ? { warnings } : {})
  };
};
