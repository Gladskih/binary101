"use strict";

import type { SignatureCursor } from "./signature-cursor.js";

const readSizes = (cursor: SignatureCursor, rank: number): number[] | null => {
  const count = cursor.readCount();
  if (count == null) return null;
  if (count > rank) return cursor.fail("array size count exceeds its rank");
  const sizes: number[] = [];
  for (let index = 0; index < count; index += 1) {
    const size = cursor.readCompressedUInt();
    if (size == null) return null;
    sizes.push(size);
  }
  return sizes;
};

const readBounds = (cursor: SignatureCursor, rank: number): number[] | null => {
  const count = cursor.readCount();
  if (count == null) return null;
  if (count > rank) return cursor.fail("array lower-bound count exceeds its rank");
  const bounds: number[] = [];
  for (let index = 0; index < count; index += 1) {
    const bound = cursor.readCompressedInt();
    if (bound == null) return null;
    bounds.push(bound);
  }
  return bounds;
};

const dimensionText = (size: number | undefined, bound: number | undefined): string => {
  if (size == null) return bound == null ? "" : `${bound}...`;
  return bound == null ? `size ${size}` : `${bound}...${bound + size - 1}`;
};

export const parseArrayShape = (cursor: SignatureCursor): string | null => {
  // ECMA-335 II.23.2.13: rank, unsigned sizes, signed lower bounds; ARRAY differs from SZARRAY.
  const rank = cursor.readCompressedUInt();
  if (rank == null) return null;
  if (rank === 0) return cursor.fail("array rank is zero");
  const sizes = readSizes(cursor, rank);
  if (!sizes) return null;
  const bounds = readBounds(cursor, rank);
  if (!bounds) return null;
  if (rank === 1 && !sizes.length && !bounds.length) return "[*]";
  // Expand only encoded dimensions; an arbitrary rank must not manufacture gigabytes of commas.
  if (rank > Math.max(sizes.length, bounds.length)) {
    return `[rank ${rank}; sizes (${sizes.join(",")}); lower bounds (${bounds.join(",")})]`;
  }
  const dimensions = Array.from({ length: rank }, (_, index) =>
    dimensionText(sizes[index], bounds[index]));
  return `[${dimensions.join(",")}]`;
};
