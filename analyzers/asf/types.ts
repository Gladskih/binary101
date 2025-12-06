"use strict";

export type NumericField = number | string | null;

export interface AsfObjectSummary {
  guid: string | null;
  name: string;
  offset: number;
  size: number | null;
  truncated: boolean;
}

export interface AsfHeaderSummary {
  size: number | null;
  objectCount: number | null;
  reserved1: number | null;
  reserved2: number | null;
  children: AsfObjectSummary[];
  truncated: boolean;
}

export interface AsfFileProperties {
  fileId: string | null;
  fileSize: NumericField;
  creationDate: string | null;
  dataPackets: NumericField;
  playDuration: NumericField;
  sendDuration: NumericField;
  prerollMs: NumericField;
  flags: number | null;
  broadcast: boolean | null;
  seekable: boolean | null;
  minPacketSize: number | null;
  maxPacketSize: number | null;
  maxBitrate: number | null;
  durationSeconds: number | null;
}

export interface AsfAudioFormat {
  kind: "audio";
  formatTag: number | null;
  formatName: string | null;
  channels: number | null;
  sampleRate: number | null;
  avgBytesPerSec: number | null;
  blockAlign: number | null;
  bitsPerSample: number | null;
  extraDataSize: number | null;
  truncated: boolean;
}

export interface AsfVideoFormat {
  kind: "video";
  width: number | null;
  height: number | null;
  bitRate: number | null;
  bitErrorRate: number | null;
  frameRate: number | null;
  bitCount: number | null;
  compression: string | null;
  imageSize: number | null;
  extraDataSize: number | null;
  truncated: boolean;
}

export interface AsfUnknownFormat {
  kind: "unknown";
  note: string;
}

export type AsfStreamFormat = AsfAudioFormat | AsfVideoFormat | AsfUnknownFormat;

export interface AsfStreamProperties {
  streamType: string | null;
  streamTypeName: string;
  errorCorrectionType: string | null;
  timeOffset: NumericField;
  typeSpecificDataLength: number | null;
  errorCorrectionDataLength: number | null;
  flags: number | null;
  streamNumber: number | null;
  encrypted: boolean | null;
  reserved: number | null;
  typeSpecific: AsfStreamFormat | null;
  truncated: boolean;
}

export interface AsfContentDescription {
  title: string;
  author: string;
  copyright: string;
  description: string;
  rating: string;
  truncated: boolean;
}

export interface AsfExtendedDescriptor {
  name: string;
  valueType: string;
  value: string;
  truncated: boolean;
}

export interface AsfCodecEntry {
  type: string;
  name: string;
  description: string;
  infoLength: number;
  truncated: boolean;
}

export interface AsfHeaderExtension {
  reserved1: string | null;
  reserved2: number | null;
  dataSize: number | null;
  objects: AsfObjectSummary[];
  truncated: boolean;
}

export interface AsfDataObject {
  fileId: string | null;
  totalPackets: NumericField;
  reserved: number | null;
  offset: number;
  size: number | null;
  truncated: boolean;
}

export interface AsfParseStats {
  parsedObjects: number;
  truncatedObjects: number;
  parsedBytes: number;
  overlayBytes: number;
}

export interface AsfParseResult {
  header: AsfHeaderSummary | null;
  objects: AsfObjectSummary[];
  fileProperties: AsfFileProperties | null;
  streams: AsfStreamProperties[];
  contentDescription: AsfContentDescription | null;
  extendedContent: AsfExtendedDescriptor[];
  codecList: AsfCodecEntry[];
  headerExtension: AsfHeaderExtension | null;
  dataObject: AsfDataObject | null;
  issues: string[];
  stats: AsfParseStats;
}
