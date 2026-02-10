"use strict";

import type { PeClrHeader } from "./clr-types.js";

export const COR20_HEADER_SIZE_BYTES = 0x48;
export const COR20_HEADER_MIN_BYTES = 0x18;

const COR20_OFFSETS = {
  cb: 0x00,
  majorRuntimeVersion: 0x04,
  minorRuntimeVersion: 0x06,
  metaDataRva: 0x08,
  metaDataSize: 0x0c,
  flags: 0x10,
  entryPointTokenOrRva: 0x14,
  resourcesRva: 0x18,
  resourcesSize: 0x1c,
  strongNameSignatureRva: 0x20,
  strongNameSignatureSize: 0x24,
  codeManagerTableRva: 0x28,
  codeManagerTableSize: 0x2c,
  vTableFixupsRva: 0x30,
  vTableFixupsSize: 0x34,
  exportAddressTableJumpsRva: 0x38,
  exportAddressTableJumpsSize: 0x3c,
  managedNativeHeaderRva: 0x40,
  managedNativeHeaderSize: 0x44
} as const;

const hasBytes = (view: DataView, offset: number, byteLength: number): boolean =>
  view.byteLength >= offset + byteLength;

const readU16LE = (view: DataView, offset: number): number =>
  hasBytes(view, offset, 2) ? view.getUint16(offset, true) : 0;

const readU32LE = (view: DataView, offset: number): number =>
  hasBytes(view, offset, 4) ? view.getUint32(offset, true) : 0;

export const readCor20Header = (view: DataView): PeClrHeader => ({
  cb: readU32LE(view, COR20_OFFSETS.cb),
  MajorRuntimeVersion: readU16LE(view, COR20_OFFSETS.majorRuntimeVersion),
  MinorRuntimeVersion: readU16LE(view, COR20_OFFSETS.minorRuntimeVersion),
  MetaDataRVA: readU32LE(view, COR20_OFFSETS.metaDataRva),
  MetaDataSize: readU32LE(view, COR20_OFFSETS.metaDataSize),
  Flags: readU32LE(view, COR20_OFFSETS.flags),
  EntryPointToken: readU32LE(view, COR20_OFFSETS.entryPointTokenOrRva),
  ResourcesRVA: readU32LE(view, COR20_OFFSETS.resourcesRva),
  ResourcesSize: readU32LE(view, COR20_OFFSETS.resourcesSize),
  StrongNameSignatureRVA: readU32LE(view, COR20_OFFSETS.strongNameSignatureRva),
  StrongNameSignatureSize: readU32LE(view, COR20_OFFSETS.strongNameSignatureSize),
  CodeManagerTableRVA: readU32LE(view, COR20_OFFSETS.codeManagerTableRva),
  CodeManagerTableSize: readU32LE(view, COR20_OFFSETS.codeManagerTableSize),
  VTableFixupsRVA: readU32LE(view, COR20_OFFSETS.vTableFixupsRva),
  VTableFixupsSize: readU32LE(view, COR20_OFFSETS.vTableFixupsSize),
  ExportAddressTableJumpsRVA: readU32LE(view, COR20_OFFSETS.exportAddressTableJumpsRva),
  ExportAddressTableJumpsSize: readU32LE(view, COR20_OFFSETS.exportAddressTableJumpsSize),
  ManagedNativeHeaderRVA: readU32LE(view, COR20_OFFSETS.managedNativeHeaderRva),
  ManagedNativeHeaderSize: readU32LE(view, COR20_OFFSETS.managedNativeHeaderSize)
});

export const buildCor20Issues = (declaredSize: number, availableSize: number): string[] => {
  const issues: string[] = [];
  if (declaredSize > 0 && declaredSize < COR20_HEADER_MIN_BYTES) {
    issues.push(
      "CLR directory is smaller than the minimum COR20 header size (0x18 bytes); " +
        "header is severely truncated."
    );
  }
  if (declaredSize > 0 && availableSize < COR20_HEADER_MIN_BYTES) {
    issues.push(
      "CLR directory does not contain a full minimum COR20 header (0x18 bytes); " +
        "some required fields are missing."
    );
  }
  if (availableSize < declaredSize) {
    issues.push(
      "CLR directory is truncated; some bytes are missing " +
        "from the end of the header region."
    );
  }
  if (declaredSize < COR20_HEADER_SIZE_BYTES) {
    issues.push(
      "CLR directory is smaller than IMAGE_COR20_HEADER (0x48 bytes); " +
        "header appears truncated."
    );
  }
  return issues;
};

