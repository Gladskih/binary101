"use strict";

// ECMA-335 II.24.2.3 (#Strings), II.23.3 (SerString): strings contain UTF-8 bytes.
// Preserve a leading U+FEFF just like MetadataReader/BlobReader; it belongs to the string.
// Reuse the decoder across heap entries; non-streaming decode resets its state on every call.
const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
export const decodeMetadataUtf8 = (bytes: Uint8Array, issues: string[], context: string): string | null => {
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    issues.push(`${context}: string is not valid UTF-8.`);
    return null;
  }
};
