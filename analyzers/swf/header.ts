import type { SwfHeader, SwfMovieHeader } from "./types.js";

// Adobe SWF v19, chapter 2: signature, version, and uncompressed FileLength.
// https://open-flash.github.io/mirrors/swf-spec-19.pdf
export const readSwfHeader = (view: DataView): SwfHeader | null => {
  if (view.byteLength < 8 || view.getUint16(1, false) !== 0x5753) return null;
  const signature = String.fromCharCode(view.getUint8(0)) + "WS";
  if (signature !== "FWS" && signature !== "CWS" && signature !== "ZWS") return null;
  const version = view.getUint8(3);
  const fileLength = view.getUint32(4, true);
  if (!version || fileLength < 14) return null;
  return { signature, version, fileLength };
};

export const readSwfLzmaHeader = (view: DataView, physicalSize: number) => {
  if (view.byteLength < 17) throw new Error("SWF LZMA header is truncated.");
  if (view.getUint8(3) < 13) throw new Error("LZMA-compressed SWF requires SWF 13 or later.");
  const compressedLength = view.getUint32(8, true);
  // JPEXS SWF.decompress: LZMAsize excludes the 17-byte prefix (including the five properties).
  // https://github.com/jindrapetrik/jpexs-decompiler/blob/master/libsrc/ffdec_lib/src/com/jpexs/decompiler/flash/SWF.java
  if (compressedLength !== physicalSize - 17 || !compressedLength) {
    throw new Error("SWF LZMA compressed length differs from the physical payload.");
  }
  const properties = Array.from({ length: 5 }, (_, index) => view.getUint8(12 + index));
  // LZMA SDK LzmaProps_Decode: the combined lc/lp/pb property must be below 9*5*5.
  // https://github.com/ip7z/7zip/blob/main/C/LzmaDec.c
  if (properties[0]! >= 9 * 5 * 5) throw new Error("SWF LZMA properties are invalid.");
  return { compressedLength, properties };
};

export const readSwfMovieHeader = (view: DataView): {
  movie: SwfMovieHeader;
  tagsOffset: number;
} => {
  if (!view.byteLength) throw new Error("SWF movie header is truncated.");
  // RECT: a 5-bit width followed by four signed coordinates, most significant bit first.
  const width = view.getUint8(0) >>> 3;
  const rectangleBytes = Math.ceil((5 + 4 * width) / 8);
  if (!width || view.byteLength < rectangleBytes + 4) {
    throw new Error("SWF RECT or frame header is truncated or has an empty bit width.");
  }
  let bitOffset = 5;
  const coordinate = (): number => {
    let value = 0;
    for (let index = 0; index < width; index++, bitOffset++) {
      value = value * 2 + ((view.getUint8(bitOffset >>> 3) >>> (7 - (bitOffset & 7))) & 1);
    }
    return value >= 2 ** (width - 1) ? value - 2 ** width : value;
  };
  return {
    movie: { xMin: coordinate(), xMax: coordinate(), yMin: coordinate(), yMax: coordinate(),
      frameRate: view.getUint16(rectangleBytes, true), frameCount: view.getUint16(rectangleBytes + 2, true) },
    tagsOffset: 8 + rectangleBytes + 4
  };
};
