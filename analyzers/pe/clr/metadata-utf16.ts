"use strict";

// ECMA-335 II.22.9: constant strings store UTF-16 code units, including unpaired surrogates.
// Preserve the units exactly; TextDecoder replaces unpaired surrogates and strips leading BOMs.
export const decodeMetadataUtf16 = (bytes: Uint8Array, issues: string[], context: string): string => {
  if (bytes.length % 2) issues.push(`${context} has a partial UTF-16 code unit.`);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let text = "";
  for (let offset = 0; offset + 1 < bytes.length; offset += 2) {
    text += String.fromCharCode(view.getUint16(offset, true));
  }
  return text;
};
