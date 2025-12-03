"use strict";

const getSafeNumber = (value: number | bigint): number | null => {
  if (typeof value === "number") return value;
  if (value <= Number.MAX_SAFE_INTEGER) return Number(value);
  return null;
};

const getBigUint64 = (dv: DataView, offset: number): bigint => dv.getBigUint64(offset, true);

const readDataView = async (
  file: File,
  offset: number | null,
  length: number
): Promise<DataView | null> => {
  if (offset == null) return null;
  if (length <= 0) return new DataView(new ArrayBuffer(0));
  const fileSize = file.size || 0;
  if (offset >= fileSize) return null;
  const clampedLength = Math.min(length, fileSize - offset);
  const buffer = await file.slice(offset, offset + clampedLength).arrayBuffer();
  return new DataView(buffer);
};

export { getBigUint64, getSafeNumber, readDataView };
