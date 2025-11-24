"use strict";

export interface GifGraphicControlExtension {
  disposalMethod: string;
  delayMs: number;
  transparentColorIndex: number | null;
  userInputFlag: boolean;
}

export interface GifFrame {
  left: number;
  top: number;
  width: number;
  height: number;
  interlaced: boolean;
  localColorCount: number;
  hasLocalColorTable: boolean;
  localColorTableSorted: boolean;
  lzwMinCodeSize: number;
  dataSize: number;
  dataTruncated: boolean;
  gce: GifGraphicControlExtension | null;
}

export interface GifApplicationExtension {
  identifier: string;
  authCode: string;
  loopCount: number | null;
  dataSize: number;
  truncated: boolean;
}

export interface GifComment {
  text: string;
  truncated: boolean;
}

export interface GifParseResult {
  size: number;
  version: string;
  width: number;
  height: number;
  hasGlobalColorTable: boolean;
  globalColorCount: number;
  globalColorTableSorted: boolean;
  colorResolutionBits: number;
  backgroundColorIndex: number;
  pixelAspectRatio: number | null;
  frames: GifFrame[];
  frameCount: number;
  loopCount: number | null;
  comments: GifComment[];
  applicationExtensions: GifApplicationExtension[];
  plainTextCount: number;
  hasTrailer: boolean;
  overlayBytes: number;
  warnings: string[];
}

