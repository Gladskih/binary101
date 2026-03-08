"use strict";

import { formatHumanSize, toHex32, toHex64 } from "../../binary-utils.js";
import { safe } from "../../html-utils.js";

const asBigInt = (value: bigint | number): bigint =>
  typeof value === "bigint" ? value : BigInt(value);

const formatHex = (value: bigint | number): string =>
  typeof value === "bigint"
    ? toHex64(value)
    : value > 0xffffffff
      ? toHex64(BigInt(value))
      : toHex32(value);

const formatByteSize = (value: bigint | number): string => {
  const bigValue = asBigInt(value);
  if (bigValue <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return formatHumanSize(Number(bigValue));
  }
  return `${bigValue} bytes`;
};

const formatFileOffset = (imageOffset: number, value: bigint | number): string => {
  const absolute = asBigInt(imageOffset) + asBigInt(value);
  if (imageOffset <= 0) return formatHex(absolute);
  return `${formatHex(absolute)} (${formatHex(value)} in slice)`;
};

const formatFileRange = (imageOffset: number, offset: bigint | number, size: bigint | number): string => {
  const absolute = asBigInt(imageOffset) + asBigInt(offset);
  const base = `${formatHex(absolute)} + ${formatByteSize(size)}`;
  if (imageOffset <= 0) return base;
  return `${base} (${formatHex(offset)} in slice)`;
};

const formatList = (items: string[]): string => (items.length ? safe(items.join(", ")) : "<span class=\"muted\">-</span>");

export { formatByteSize, formatFileOffset, formatFileRange, formatHex, formatList };
