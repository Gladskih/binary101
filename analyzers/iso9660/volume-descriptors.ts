"use strict";

import type {
  Iso9660BootRecordDescriptor,
  Iso9660PrimaryVolumeDescriptor,
  Iso9660StringEncoding,
  Iso9660SupplementaryVolumeDescriptor,
  Iso9660VolumeDescriptorSummary
} from "./types.js";
import {
  decodeAsciiField,
  decodeStringField,
  describeVolumeDescriptorType,
  parseVolumeDateTime17,
  readBothEndianUint16,
  readBothEndianUint32,
  readUint32Be,
  readUint32Le
} from "./iso-parsing.js";
import { parseDirectoryRecord } from "./directory-records.js";

const JOLIET_ESCAPES: Record<string, number> = {
  "%/@": 1,
  "%/C": 2,
  "%/E": 3
};

export const isJolietEscapeSequence = (value: string | null): { isJoliet: boolean; level: number | null } => {
  if (!value) return { isJoliet: false, level: null };
  const trimmed = value.trimEnd();
  const level = JOLIET_ESCAPES[trimmed];
  return { isJoliet: level != null, level: level ?? null };
};

export const parseDescriptorSummary = (
  bytes: Uint8Array,
  sector: number,
  byteOffset: number
): Iso9660VolumeDescriptorSummary | null => {
  if (bytes.length < 7) return null;
  const typeCode = bytes[0] ?? 0;
  const identifier = decodeAsciiField(bytes, 1, 5);
  const version = bytes.length >= 7 ? (bytes[6] ?? 0) : null;
  return {
    sector,
    byteOffset,
    typeCode,
    typeName: describeVolumeDescriptorType(typeCode),
    identifier,
    version
  };
};

const parseCommonVolumeDescriptorFields = (
  bytes: Uint8Array,
  absoluteBaseOffset: number,
  encoding: Iso9660StringEncoding,
  pushIssue: (message: string) => void
): Iso9660PrimaryVolumeDescriptor => ({
  systemIdentifier: decodeStringField(bytes, 8, 32, encoding),
  volumeIdentifier: decodeStringField(bytes, 40, 32, encoding),
  volumeSpaceSizeBlocks: readBothEndianUint32(bytes, 80, absoluteBaseOffset, "Volume space size", pushIssue),
  volumeSetSize: readBothEndianUint16(bytes, 120, absoluteBaseOffset, "Volume set size", pushIssue),
  volumeSequenceNumber: readBothEndianUint16(bytes, 124, absoluteBaseOffset, "Volume sequence number", pushIssue),
  logicalBlockSize: readBothEndianUint16(bytes, 128, absoluteBaseOffset, "Logical block size", pushIssue),
  pathTableSize: readBothEndianUint32(bytes, 132, absoluteBaseOffset, "Path table size", pushIssue),
  typeLPathTableLocation: readUint32Le(bytes, 140),
  optionalTypeLPathTableLocation: readUint32Le(bytes, 144),
  typeMPathTableLocation: readUint32Be(bytes, 148),
  optionalTypeMPathTableLocation: readUint32Be(bytes, 152),
  rootDirectoryRecord: parseDirectoryRecord(bytes, 156, absoluteBaseOffset, encoding, pushIssue, {
    zeroIdentifierMeaning: "root"
  }),
  volumeSetIdentifier: decodeStringField(bytes, 190, 128, encoding),
  publisherIdentifier: decodeStringField(bytes, 318, 128, encoding),
  dataPreparerIdentifier: decodeStringField(bytes, 446, 128, encoding),
  applicationIdentifier: decodeStringField(bytes, 574, 128, encoding),
  copyrightFileIdentifier: decodeStringField(bytes, 702, 37, encoding),
  abstractFileIdentifier: decodeStringField(bytes, 739, 37, encoding),
  bibliographicFileIdentifier: decodeStringField(bytes, 776, 37, encoding),
  volumeCreationDateTime: parseVolumeDateTime17(bytes, 813),
  volumeModificationDateTime: parseVolumeDateTime17(bytes, 830),
  volumeExpirationDateTime: parseVolumeDateTime17(bytes, 847),
  volumeEffectiveDateTime: parseVolumeDateTime17(bytes, 864),
  fileStructureVersion: bytes.length > 881 ? (bytes[881] ?? 0) : null
});

export const parsePrimaryVolumeDescriptor = (
  bytes: Uint8Array,
  absoluteBaseOffset: number,
  pushIssue: (message: string) => void
): Iso9660PrimaryVolumeDescriptor => parseCommonVolumeDescriptorFields(bytes, absoluteBaseOffset, "ascii", pushIssue);

export const parseSupplementaryVolumeDescriptor = (
  bytes: Uint8Array,
  absoluteBaseOffset: number,
  pushIssue: (message: string) => void
): Iso9660SupplementaryVolumeDescriptor => {
  const escapeSequences = decodeAsciiField(bytes, 88, 32);
  const joliet = isJolietEscapeSequence(escapeSequences);
  const encoding: Iso9660StringEncoding = joliet.isJoliet ? "ucs2be" : "ascii";
  return {
    ...parseCommonVolumeDescriptorFields(bytes, absoluteBaseOffset, encoding, pushIssue),
    escapeSequences,
    isJoliet: joliet.isJoliet,
    jolietLevel: joliet.level
  };
};

export const parseBootRecordDescriptor = (
  bytes: Uint8Array
): Iso9660BootRecordDescriptor => {
  const bootSystemIdentifier = decodeAsciiField(bytes, 7, 32);
  const bootIdentifier = decodeAsciiField(bytes, 39, 32);
  let elToritoCatalogLba: number | null = null;
  if (bootSystemIdentifier?.trimEnd() === "EL TORITO SPECIFICATION") {
    elToritoCatalogLba = readUint32Le(bytes, 71);
  }
  return {
    bootSystemIdentifier,
    bootIdentifier,
    elToritoCatalogLba
  };
};

