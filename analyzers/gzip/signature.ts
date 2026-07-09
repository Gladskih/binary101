"use strict";

// RFC 1952, section 2.3.1: gzip ID1=0x1f, ID2=0x8b, CM=8 means "deflate".
// https://www.rfc-editor.org/rfc/rfc1952#section-2.3.1
export const GZIP_ID1 = 0x1f;
export const GZIP_ID2 = 0x8b;
export const GZIP_DEFLATE_COMPRESSION_METHOD = 8;
export const GZIP_BASE_HEADER_BYTES = 10;
export const GZIP_FLAG_FTEXT = 0x01;
export const GZIP_FLAG_FHCRC = 0x02;
export const GZIP_FLAG_FEXTRA = 0x04;
export const GZIP_FLAG_FNAME = 0x08;
export const GZIP_FLAG_FCOMMENT = 0x10;
export const GZIP_RESERVED_FLAGS_MASK = 0xe0;

export const hasGzipDeflateHeaderBytes = (bytes: Uint8Array): boolean =>
  bytes[0] === GZIP_ID1 &&
  bytes[1] === GZIP_ID2 &&
  bytes[2] === GZIP_DEFLATE_COMPRESSION_METHOD;

export const hasValidGzipDeflateHeaderView = (view: DataView): boolean =>
  view.byteLength >= GZIP_BASE_HEADER_BYTES &&
  view.getUint8(0) === GZIP_ID1 &&
  view.getUint8(1) === GZIP_ID2 &&
  view.getUint8(2) === GZIP_DEFLATE_COMPRESSION_METHOD &&
  (view.getUint8(3) & GZIP_RESERVED_FLAGS_MASK) === 0;
