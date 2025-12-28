"use strict";

export type Iso9660StringEncoding = "ascii" | "ucs2be";

export type Iso9660VolumeDescriptorSummary = {
  sector: number;
  byteOffset: number;
  typeCode: number;
  typeName: string;
  identifier: string | null;
  version: number | null;
};

export type Iso9660DirectoryRecord = {
  recordLength: number;
  extendedAttributeRecordLength: number;
  extentLocationLba: number | null;
  dataLength: number | null;
  recordingDateTime: string | null;
  utcOffsetMinutes: number | null;
  fileFlags: number;
  fileUnitSize: number;
  interleaveGapSize: number;
  volumeSequenceNumber: number | null;
  fileIdentifierRaw: string | null;
  fileIdentifier: string | null;
  fileVersion: number | null;
  isDirectory: boolean;
  isDotEntry: boolean;
  isDotDotEntry: boolean;
  systemUseLength: number;
};

export type Iso9660PrimaryVolumeDescriptor = {
  systemIdentifier: string | null;
  volumeIdentifier: string | null;
  volumeSpaceSizeBlocks: number | null;
  volumeSetSize: number | null;
  volumeSequenceNumber: number | null;
  logicalBlockSize: number | null;
  pathTableSize: number | null;
  typeLPathTableLocation: number | null;
  optionalTypeLPathTableLocation: number | null;
  typeMPathTableLocation: number | null;
  optionalTypeMPathTableLocation: number | null;
  rootDirectoryRecord: Iso9660DirectoryRecord | null;
  volumeSetIdentifier: string | null;
  publisherIdentifier: string | null;
  dataPreparerIdentifier: string | null;
  applicationIdentifier: string | null;
  copyrightFileIdentifier: string | null;
  abstractFileIdentifier: string | null;
  bibliographicFileIdentifier: string | null;
  volumeCreationDateTime: string | null;
  volumeModificationDateTime: string | null;
  volumeExpirationDateTime: string | null;
  volumeEffectiveDateTime: string | null;
  fileStructureVersion: number | null;
};

export type Iso9660SupplementaryVolumeDescriptor = Iso9660PrimaryVolumeDescriptor & {
  escapeSequences: string | null;
  isJoliet: boolean;
  jolietLevel: number | null;
};

export type Iso9660BootRecordDescriptor = {
  bootSystemIdentifier: string | null;
  bootIdentifier: string | null;
  elToritoCatalogLba: number | null;
};

export type Iso9660PathTableEntry = {
  index: number;
  identifier: string | null;
  extentLocationLba: number | null;
  parentDirectoryIndex: number | null;
};

export type Iso9660PathTable = {
  locationLba: number | null;
  declaredSize: number | null;
  bytesRead: number;
  entryCount: number;
  entries: Iso9660PathTableEntry[];
  omittedEntries: number;
};

export type Iso9660DirectoryEntrySummary = {
  name: string;
  kind: "file" | "directory" | "special";
  extentLocationLba: number | null;
  dataLength: number | null;
  fileFlags: number;
  recordingDateTime: string | null;
};

export type Iso9660DirectoryListing = {
  extentLocationLba: number | null;
  byteOffset: number | null;
  declaredSize: number | null;
  bytesRead: number;
  totalEntries: number;
  entries: Iso9660DirectoryEntrySummary[];
  omittedEntries: number;
};

export type Iso9660DirectoryTraversalStats = {
  scannedDirectories: number;
  scannedFiles: number;
  maxDepth: number;
  omittedDirectories: number;
  omittedEntries: number;
  loopDetections: number;
};

export type Iso9660ParseResult = {
  isIso9660: true;
  fileSize: number;
  descriptorBlockSize: number;
  descriptors: Iso9660VolumeDescriptorSummary[];
  primaryVolume: Iso9660PrimaryVolumeDescriptor | null;
  supplementaryVolumes: Iso9660SupplementaryVolumeDescriptor[];
  bootRecords: Iso9660BootRecordDescriptor[];
  volumePartitionDescriptorCount: number;
  terminatorSector: number | null;
  selectedEncoding: Iso9660StringEncoding;
  selectedBlockSize: number;
  pathTable: Iso9660PathTable | null;
  rootDirectory: Iso9660DirectoryListing | null;
  traversal: Iso9660DirectoryTraversalStats | null;
  issues: string[];
};

