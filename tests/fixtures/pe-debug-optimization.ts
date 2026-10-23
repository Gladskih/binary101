import type { PeMpxInfo } from "../../analyzers/pe/debug/mpx.js";

// PE Bliss 2, image_debug_mpx: JRBP, unknown1, flags, unknown2, unknown3.
// https://github.com/dragon-dreamer/pe_bliss2/blob/e4d56862f2ccd9ed33fa5d4f6c51dfc4d075996f/pe_bliss2/include/pe_bliss2/detail/debug/image_debug_directory.h#L295
export const createMpxPayload = (
  info: PeMpxInfo = { flags: 5, unknown1: 0, unknown2: 0, unknown3: 0 }
): Uint8Array => {
  const bytes = new Uint8Array(20);
  const view = new DataView(bytes.buffer);
  [0x5042524a, info.unknown1, info.flags, info.unknown2, info.unknown3].forEach(
    (value, index) => view.setUint32(index * 4, value, true));
  return bytes;
};

// SPGO type 18 stores a UTF-16LE C string, independently of POGO type 13.
// https://github.com/dragon-dreamer/pe_bliss2/blob/e4d56862f2ccd9ed33fa5d4f6c51dfc4d075996f/pe_bliss2/src/debug/debug_directory.cpp#L210
export const createSpgoPayload = (text = "sample.spd"): Uint8Array => {
  const bytes = new Uint8Array((text.length + 1) * 2);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < text.length; index += 1) {
    view.setUint16(index * 2, text.charCodeAt(index), true);
  }
  return bytes;
};
