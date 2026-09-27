"use strict";

import type { ResourceFontPreview } from "./font-types.js";

// Packed FONTDIRENTRY offsets; the fixed portion is 113 bytes, without C struct padding.
// https://learn.microsoft.com/en-us/windows/win32/menurc/fontdirentry
// https://squeek502.github.io/resinator/windows/resources/font.html
export const readFontHeader = (data: Uint8Array, offset: number): ResourceFontPreview | null => {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + 113 > data.length) return null;
  const view = new DataView(data.buffer, data.byteOffset + offset, 113);
  const copyright = data.subarray(offset + 6, offset + 66);
  const copyrightEnd = copyright.indexOf(0);
  return {
    version: view.getUint16(0, true), fileSize: view.getUint32(2, true),
    copyright: new TextDecoder("windows-1252").decode(
      copyright.subarray(0, copyrightEnd < 0 ? copyright.length : copyrightEnd)),
    type: view.getUint16(66, true), pointSize: view.getUint16(68, true),
    verticalResolution: view.getUint16(70, true), horizontalResolution: view.getUint16(72, true),
    ascent: view.getUint16(74, true), internalLeading: view.getUint16(76, true),
    externalLeading: view.getUint16(78, true), italic: view.getUint8(80) !== 0,
    underline: view.getUint8(81) !== 0, strikeOut: view.getUint8(82) !== 0,
    weight: view.getUint16(83, true), charset: view.getUint8(85),
    pixelWidth: view.getUint16(86, true), pixelHeight: view.getUint16(88, true),
    pitchAndFamily: view.getUint8(90), averageWidth: view.getUint16(91, true),
    maximumWidth: view.getUint16(93, true), firstChar: view.getUint8(95), lastChar: view.getUint8(96),
    defaultChar: view.getUint8(97), breakChar: view.getUint8(98), widthBytes: view.getUint16(99, true),
    deviceName: "", faceName: ""
  };
};

export const readFontName = (
  data: Uint8Array, offset: number, issues: string[]
): { text: string; nextOffset: number } => {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= data.length) {
    issues.push("Font name offset is outside the resource.");
    return { text: "", nextOffset: data.length };
  }
  const terminator = data.indexOf(0, offset);
  if (terminator < 0) issues.push("Font name is not NUL-terminated within the resource.");
  const bytes = data.subarray(offset, terminator < 0 ? data.length : terminator);
  if (bytes.some(byte => byte >= 0x80)) issues.push("Font name ANSI code page is unspecified; displaying Windows-1252.");
  return { text: new TextDecoder("windows-1252").decode(bytes),
    nextOffset: terminator < 0 ? data.length : terminator + 1 };
};
