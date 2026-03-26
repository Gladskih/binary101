"use strict";

type ByteSource = DataView | Uint8Array;

const readByte = (data: ByteSource, offset: number): number =>
  data instanceof DataView ? data.getUint8(offset) : (data[offset] ?? -1);

export const hasBytePrefix = (data: ByteSource, prefix: number[]): boolean =>
  data.byteLength >= prefix.length &&
  prefix.every((value, index) => readByte(data, index) === value);

// PNG datastreams always begin with this 8-byte signature. Source:
// W3C PNG Specification, "File signature" / https://www.w3.org/TR/REC-png/#5PNG-file-signature
export const hasPngSignature = (data: ByteSource): boolean =>
  hasBytePrefix(data, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

// WHATWG MIME Sniffing Standard, "Matching an image type pattern", defines JPEG as the
// Start Of Image marker 0xFF 0xD8 followed by another marker introducer 0xFF.
// https://mimesniff.spec.whatwg.org/#matching-an-image-type-pattern
export const hasJpegSignature = (data: ByteSource): boolean =>
  hasBytePrefix(data, [0xff, 0xd8, 0xff]);

// Lightweight JPEG gate for top-level label probes: the shared probe layer keeps accepting any
// Start Of Image marker (0xFFD8) so short JFIF/Exif buffers continue to identify as JPEG before
// deeper parsers or preview-specific stricter checks run.
export const hasJpegStartOfImage = (data: ByteSource): boolean =>
  hasBytePrefix(data, [0xff, 0xd8]);

// WHATWG MIME Sniffing Standard, "Matching an image type pattern", recognizes GIF87a/GIF89a.
// https://mimesniff.spec.whatwg.org/#matching-an-image-type-pattern
export const hasGifSignature = (data: ByteSource): boolean =>
  hasBytePrefix(data, [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]) ||
  hasBytePrefix(data, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]);

// WHATWG MIME Sniffing Standard, "Matching an image type pattern", recognizes BMP by "BM".
// https://mimesniff.spec.whatwg.org/#matching-an-image-type-pattern
export const hasBmpSignature = (data: ByteSource): boolean =>
  hasBytePrefix(data, [0x42, 0x4d]);

// WHATWG MIME Sniffing Standard, "Matching an image type pattern", recognizes WebP as a RIFF
// container with the WEBPVP prefix.
// https://mimesniff.spec.whatwg.org/#matching-an-image-type-pattern
export const hasWebpSignature = (data: ByteSource): boolean =>
  hasBytePrefix(data, [0x52, 0x49, 0x46, 0x46]) &&
  readByte(data, 8) === 0x57 &&
  readByte(data, 9) === 0x45 &&
  readByte(data, 10) === 0x42 &&
  readByte(data, 11) === 0x50 &&
  readByte(data, 12) === 0x56 &&
  readByte(data, 13) === 0x50;

// WHATWG MIME Sniffing Standard, "Matching a font type pattern", recognizes TrueType/OpenType
// sfnt payloads with the 0x00010000 scaler value.
// https://mimesniff.spec.whatwg.org/#matching-a-font-type-pattern
export const hasTrueTypeSfntSignature = (data: ByteSource): boolean =>
  hasBytePrefix(data, [0x00, 0x01, 0x00, 0x00]);

// WHATWG MIME Sniffing Standard, "Matching a font type pattern", recognizes OpenType CFF by
// the "OTTO" sfnt tag.
// https://mimesniff.spec.whatwg.org/#matching-a-font-type-pattern
export const hasOpenTypeCffSignature = (data: ByteSource): boolean =>
  hasBytePrefix(data, [0x4f, 0x54, 0x54, 0x4f]);

// WHATWG MIME Sniffing Standard, "Matching a font type pattern", recognizes WOFF by "wOFF".
// https://mimesniff.spec.whatwg.org/#matching-a-font-type-pattern
export const hasWoffSignature = (data: ByteSource): boolean =>
  hasBytePrefix(data, [0x77, 0x4f, 0x46, 0x46]);

// WHATWG MIME Sniffing Standard, "Matching a font type pattern", recognizes WOFF2 by "wOF2".
// https://mimesniff.spec.whatwg.org/#matching-a-font-type-pattern
export const hasWoff2Signature = (data: ByteSource): boolean =>
  hasBytePrefix(data, [0x77, 0x4f, 0x46, 0x32]);

// Adobe PDF Reference 1.7, section 7.5.2 "File Header", uses the "%PDF-" prefix.
// https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/pdfreference1.7old.pdf
export const hasPdfHeader = (data: ByteSource): boolean =>
  hasBytePrefix(data, [0x25, 0x50, 0x44, 0x46, 0x2d]);

// WHATWG MIME Sniffing Standard, "Matching an archive type pattern", recognizes ZIP local file
// headers by "PK 03 04".
// https://mimesniff.spec.whatwg.org/#matching-an-archive-type-pattern
export const hasZipLocalFileHeader = (data: ByteSource): boolean =>
  hasBytePrefix(data, [0x50, 0x4b, 0x03, 0x04]);

export const hasRiffForm = (data: ByteSource, formType: string): boolean => {
  // RIFF files start with a 12-byte header: "RIFF", a 32-bit size, and a 4-byte form type.
  return formType.length === 4 &&
    hasBytePrefix(data, [0x52, 0x49, 0x46, 0x46]) &&
    readByte(data, 8) === formType.charCodeAt(0) &&
    readByte(data, 9) === formType.charCodeAt(1) &&
    readByte(data, 10) === formType.charCodeAt(2) &&
    readByte(data, 11) === formType.charCodeAt(3);
};
