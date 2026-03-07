"use strict";

import { formatHumanSize, toHex32, toHex64 } from "../../binary-utils.js";
import { safe } from "../../html-utils.js";

const formatHex = (value: bigint | number): string =>
  typeof value === "bigint"
    ? toHex64(value)
    : value > 0xffffffff
      ? toHex64(BigInt(value))
      : toHex32(value);

const formatByteSize = (value: bigint | number): string => {
  const asBigInt = typeof value === "bigint" ? value : BigInt(value >>> 0);
  if (asBigInt <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return formatHumanSize(Number(asBigInt));
  }
  return `${asBigInt} bytes`;
};

const formatList = (items: string[]): string => (items.length ? safe(items.join(", ")) : "<span class=\"muted\">-</span>");

export { formatByteSize, formatHex, formatList };
