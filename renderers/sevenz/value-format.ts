"use strict";

import { formatHumanSize, toHex32 } from "../../binary-utils.js";

export const formatOffset = (value: number | bigint | null | undefined): string => {
  if (value == null) return "-";
  if (typeof value === "bigint") return `0x${value.toString(16)}`;
  return toHex32(value, 8);
};

export const formatSize = (value: number | bigint | null | undefined): string => {
  if (value == null) return "-";
  if (typeof value === "bigint") {
    if (value <= BigInt(Number.MAX_SAFE_INTEGER)) {
      return formatHumanSize(Number(value));
    }
    return `${value.toString()} bytes`;
  }
  return formatHumanSize(value);
};

const toSafeNumber = (value: number | bigint | null | undefined): number | null => {
  if (typeof value === "number") return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  return null;
};

export const formatSizeDetailed = (value: number | bigint | null | undefined): string => {
  if (value == null) return "-";
  const safeNumber = toSafeNumber(value);
  if (safeNumber != null) return formatHumanSize(safeNumber);
  const asBigInt = typeof value === "bigint" ? value : BigInt(Math.max(value, 0));
  return `${asBigInt.toString()} bytes`;
};

export const formatRatio = (value: number | null | undefined): string => {
  if (value == null || !Number.isFinite(value)) return "-";
  return `${value.toFixed(1)}%`;
};

