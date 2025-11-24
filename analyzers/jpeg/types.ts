"use strict";

export interface ExifRational {
  num: number;
  den: number;
}

export interface ExifGps {
  latRef: string | null;
  lat: ExifRational[] | null;
  lonRef: string | null;
  lon: ExifRational[] | null;
}

export interface ExifRawTag {
  ifd: string;
  tag: number;
  type: number;
  count: number;
  preview: string;
}

export interface ExifData {
  orientation: number | null;
  make: string | null;
  model: string | null;
  dateTimeOriginal: string | null;
  iso: number | null;
  exposureTime: ExifRational | null;
  fNumber: ExifRational | null;
  focalLength: ExifRational | null;
  flash: number | null;
  pixelXDimension: number | null;
  pixelYDimension: number | null;
  gps: ExifGps | null;
  rawTags: ExifRawTag[];
}

export interface JpegSof {
  marker: number;
  markerName: string;
  precision: number;
  width: number | null;
  height: number | null;
  components: number;
}

export interface JpegJfif {
  versionMajor: number;
  versionMinor: number;
  units: number;
  xDensity: number | null;
  yDensity: number | null;
  xThumbnail: number;
  yThumbnail: number;
}

export interface JpegComment {
  text: string;
  truncated: boolean;
}

export interface JpegSegment {
  marker: number;
  name: string;
  offset: number;
  length: number;
  info?: unknown;
}

export interface JpegParseResult {
  size: number;
  sof: JpegSof | null;
  hasJfif: boolean;
  hasExif: boolean;
  hasIcc: boolean;
  hasAdobe: boolean;
  hasRar: boolean;
  hasEoi: boolean;
  segmentCount: number;
  segments: JpegSegment[];
  comments: JpegComment[];
  jfif: JpegJfif | null;
  exif: ExifData | null;
}
