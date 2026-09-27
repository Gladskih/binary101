export interface ResourceFontPreview {
  version: number;
  fileSize: number;
  copyright: string;
  type: number;
  pointSize: number;
  verticalResolution: number;
  horizontalResolution: number;
  ascent: number;
  internalLeading: number;
  externalLeading: number;
  italic: boolean;
  underline: boolean;
  strikeOut: boolean;
  weight: number;
  charset: number;
  pixelWidth: number;
  pixelHeight: number;
  pitchAndFamily: number;
  averageWidth: number;
  maximumWidth: number;
  firstChar: number;
  lastChar: number;
  defaultChar: number;
  breakChar: number;
  widthBytes: number;
  deviceName: string;
  faceName: string;
}

export interface ResourceFontDirectory {
  headerSize: number;
  entries: Array<{ ordinal: number; font: ResourceFontPreview }>;
}
