"use strict";

export type FlacMetadataBlockType =
  | "STREAMINFO"
  | "PADDING"
  | "APPLICATION"
  | "SEEKTABLE"
  | "VORBIS_COMMENT"
  | "CUESHEET"
  | "PICTURE"
  | "UNKNOWN";

export interface FlacMetadataBlock {
  type: FlacMetadataBlockType;
  rawType: number;
  isLast: boolean;
  length: number;
  offset: number;
  truncated: boolean;
}

export interface FlacStreamInfo {
  minBlockSize: number | null;
  maxBlockSize: number | null;
  minFrameSize: number | null;
  maxFrameSize: number | null;
  sampleRate: number | null;
  channels: number | null;
  bitsPerSample: number | null;
  totalSamples: number | null;
  md5: string | null;
  durationSeconds: number | null;
  averageBitrateKbps: number | null;
}

export interface FlacStreamInfoBlock extends FlacMetadataBlock {
  type: "STREAMINFO";
  info: FlacStreamInfo | null;
}

export interface FlacPaddingBlock extends FlacMetadataBlock {
  type: "PADDING";
}

export interface FlacApplicationBlock extends FlacMetadataBlock {
  type: "APPLICATION";
  id: string | null;
  rawId: number | null;
  dataLength: number | null;
}

export interface FlacSeekPoint {
  sampleNumber: bigint | null;
  streamOffset: bigint | null;
  frameSamples: number | null;
  placeholder: boolean;
}

export interface FlacSeekTableBlock extends FlacMetadataBlock {
  type: "SEEKTABLE";
  points: FlacSeekPoint[];
  parsedEntries: number;
}

export interface FlacVorbisComment {
  key: string;
  value: string;
}

export interface FlacVorbisCommentBlock extends FlacMetadataBlock {
  type: "VORBIS_COMMENT";
  vendor: string | null;
  commentCount: number | null;
  comments: FlacVorbisComment[];
}

export interface FlacCueSheetBlock extends FlacMetadataBlock {
  type: "CUESHEET";
  catalog: string | null;
  leadInSamples: bigint | null;
  isCd: boolean | null;
  trackCount: number | null;
}

export interface FlacPictureBlock extends FlacMetadataBlock {
  type: "PICTURE";
  pictureType: number | null;
  mimeType: string | null;
  description: string | null;
  width: number | null;
  height: number | null;
  depth: number | null;
  colors: number | null;
  dataLength: number | null;
}

export interface FlacUnknownBlock extends FlacMetadataBlock {
  type: "UNKNOWN";
}

export type FlacMetadataBlockDetail =
  | FlacStreamInfoBlock
  | FlacPaddingBlock
  | FlacApplicationBlock
  | FlacSeekTableBlock
  | FlacVorbisCommentBlock
  | FlacCueSheetBlock
  | FlacPictureBlock
  | FlacUnknownBlock;

export interface FlacParseResult {
  isFlac: boolean;
  streamInfo: FlacStreamInfo | null;
  blocks: FlacMetadataBlockDetail[];
  audioDataOffset: number | null;
  audioDataBytes: number | null;
  warnings: string[];
}
