"use strict";

export interface RiffParserOptions {
  maxChunks?: number;
  maxDepth?: number;
}

export interface RiffChunk {
  id: string | null;
  offset: number;
  size: number;
  dataOffset: number;
  dataEnd: number;
  paddedSize: number;
  paddingBytes: number;
  truncated: boolean;
  listType: string | null;
  children: RiffChunk[] | null;
  depth: number;
  inParentLimit: boolean;
}

export interface RiffStats {
  chunkCount: number;
  listCount: number;
  maxDepth: number;
  parsedBytes: number;
  overlayBytes: number;
  paddingBytes: number;
  truncatedChunks: number;
  stoppedEarly: boolean;
}

export interface RiffParseResult {
  signature: "RIFF" | "RIFX";
  littleEndian: boolean;
  riffSize: number;
  expectedSize: number;
  formType: string | null;
  fileSize: number;
  chunks: RiffChunk[];
  stats: RiffStats;
  issues: string[];
}
