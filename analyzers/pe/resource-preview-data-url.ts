"use strict";

const base64FromU8 = (u8: Uint8Array): string => {
  let out = "";
  for (let index = 0; index < u8.length; index += 0x8000) {
    out += String.fromCharCode(...u8.subarray(index, index + 0x8000));
  }
  return btoa(out);
};

export const makeDataUrl = (mimeType: string, bytes: Uint8Array): string =>
  `data:${mimeType};base64,${base64FromU8(bytes)}`;
