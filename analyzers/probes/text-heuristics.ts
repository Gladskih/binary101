"use strict";

const MAX_TEXT_INSPECT_BYTES = 256;

const toAsciiPrefix = (dv: DataView, maxBytes: number): string => {
  const limit = Math.min(dv.byteLength, maxBytes);
  let result = "";
  for (let i = 0; i < limit; i += 1) {
    const code = dv.getUint8(i);
    if (code === 0) break;
    if (code < 0x09) return "";
    result += String.fromCharCode(code);
  }
  return result;
};

const isMostlyText = (dv: DataView): boolean => {
  if (dv.byteLength === 0) return false;
  const limit = Math.min(dv.byteLength, MAX_TEXT_INSPECT_BYTES);
  let printable = 0;
  let control = 0;
  for (let i = 0; i < limit; i += 1) {
    const c = dv.getUint8(i);
    if (c === 0) {
      control += 1;
      continue;
    }
    if (c === 0x09 || c === 0x0a || c === 0x0d) {
      printable += 1;
      continue;
    }
    if (c >= 0x20 && c <= 0x7e) {
      printable += 1;
    } else {
      control += 1;
    }
  }
  return printable > 0 && control * 4 <= printable;
};

export { isMostlyText, toAsciiPrefix, MAX_TEXT_INSPECT_BYTES };
