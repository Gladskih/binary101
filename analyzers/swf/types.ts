export interface SwfHeader {
  signature: "FWS" | "CWS" | "ZWS";
  version: number;
  fileLength: number;
}

export interface SwfMovieHeader {
  xMin: number;
  xMax: number;
  yMin: number;
  yMax: number;
  frameRate: number;
  frameCount: number;
}

export interface SwfTag {
  code: number;
  count: number;
  bodyBytes: number;
}

export interface SwfParseResult extends SwfHeader {
  movie?: SwfMovieHeader;
  fileAttributes?: number;
  lzma?: { compressedLength: number; properties: number[] };
  tags?: SwfTag[];
  tagEnd?: number;
  issues: string[];
}
