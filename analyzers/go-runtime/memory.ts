"use strict";

import type { GoRuntimeAddressSpace } from "./types.js";

export const readWord = (
  view: DataView,
  offset: number,
  pointerSize: 4 | 8
): bigint => pointerSize === 8
  ? view.getBigUint64(offset, true)
  : BigInt(view.getUint32(offset, true));

export const readExact = async (
  image: GoRuntimeAddressSpace,
  address: bigint,
  size: number
): Promise<Uint8Array | null> => {
  if (!Number.isSafeInteger(size) || size < 0 || !image.isMappedRange(address, size)) return null;
  const bytes = await image.readMapped(address, size);
  return bytes?.byteLength === size ? bytes : null;
};

export const toView = (bytes: Uint8Array): DataView =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
