"use strict";

import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import { safe } from "../../html-utils.js";

export const formatElfHex = (value: bigint | number, width?: number): string => {
  if (typeof value === "bigint") {
    const hex = value.toString(16);
    const pad = width ? hex.padStart(width, "0") : hex;
    return `0x${pad}`;
  }
  return toHex32(value, width || 0);
};

export const formatElfList = (values: string[] | null | undefined): string =>
  values && values.length ? safe(values.join(", ")) : "-";

export const formatElfMaybeHumanSize = (value: bigint): string => {
  const num = Number(value);
  if (Number.isSafeInteger(num) && num >= 0) {
    return `<span title="${safe(formatElfHex(value))}">${safe(formatHumanSize(num))}</span>`;
  }
  return safe(formatElfHex(value));
};

