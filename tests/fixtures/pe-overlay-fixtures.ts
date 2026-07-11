"use strict";

import { MockFile } from "../helpers/mock-file.js";

export const createOverlayInputsWithPayload = (payloadBytes: Uint8Array) => {
  const imagePrefixBytes = new Uint8Array(Uint8Array.BYTES_PER_ELEMENT);
  const overlayStart = imagePrefixBytes.byteLength;
  const overlayEnd = overlayStart + payloadBytes.byteLength;
  const bytes = new Uint8Array(overlayEnd);
  bytes.set(imagePrefixBytes);
  bytes.set(payloadBytes, overlayStart);
  const file = new MockFile(bytes, "carrier.exe");
  return {
    overlayEnd,
    overlayStart,
    inputs: {
      file,
      reader: file,
      optionalHeaderOffset: 0,
      optionalHeaderSize: 0,
      sectionCount: 0,
      declaredSizeOfHeaders: overlayStart,
      sections: [],
      dataDirs: [],
      pointerToSymbolTable: 0,
      numberOfSymbols: 0
    }
  };
};
