"use strict";

import { readGuid } from "./utils.js";
import { parsePropertyValue, propertyKeyLabel } from "./property-values.js";
import type { LnkProperty, LnkPropertyStorage, LnkPropertyStoreData } from "./types.js";

const parsePropertyStorage = (
  dv: DataView,
  warnings: string[],
  formatId: string | null
): { properties: LnkProperty[]; endOffset: number } => {
  const properties: LnkProperty[] = [];
  let cursor = 0;
  const limit = dv.byteLength;
  while (cursor + 8 <= limit) {
    const valueSize = dv.getUint32(cursor, true);
    const propertyId = dv.getUint32(cursor + 4, true);
    if (valueSize === 0 && propertyId === 0) break;
    const valueOffset = cursor + 8;
    const valueEnd = valueOffset + valueSize;
    const step = Math.max(8, 8 + valueSize);
    const truncated = valueEnd > limit;
    const propertyValue = parsePropertyValue(
      new DataView(dv.buffer, dv.byteOffset),
      valueOffset,
      valueSize,
      warnings,
      `${formatId}:${propertyId}`
    );
    properties.push({
      id: propertyId,
      name: propertyKeyLabel(formatId, propertyId),
      ...propertyValue,
      truncated: propertyValue.truncated || truncated
    });
    cursor += step;
  }
  return { properties, endOffset: cursor };
};

const parsePropertyStore = (blockDv: DataView, warnings: string[]): LnkPropertyStoreData => {
  const storages: LnkPropertyStorage[] = [];
  const limit = blockDv.byteLength;
  let cursor = 8;
  while (cursor + 24 <= limit) {
    const storageSize = blockDv.getUint32(cursor, true);
    if (storageSize === 0) break;
    if (storageSize < 24) {
      warnings.push("Property store storage is smaller than minimum header size.");
      break;
    }
    const magicValue = blockDv.getUint32(cursor + 4, true);
    let magic: string;
    if (magicValue === 0x53505331) {
      magic = "SPS1";
    } else if (magicValue === 0x53505332) {
      magic = "SPS2";
    } else {
      magic =
        String.fromCharCode(blockDv.getUint8(cursor + 4)) +
        String.fromCharCode(blockDv.getUint8(cursor + 5)) +
        String.fromCharCode(blockDv.getUint8(cursor + 6)) +
        String.fromCharCode(blockDv.getUint8(cursor + 7));
    }
    const formatId = readGuid(blockDv, cursor + 8);
    const storageStart = cursor + 24;
    const storageEnd = cursor + storageSize;
    const truncated = storageEnd > limit;
    const storageView = new DataView(
      blockDv.buffer,
      blockDv.byteOffset + storageStart,
      Math.max(0, limit - storageStart)
    );
    const { properties } = parsePropertyStorage(storageView, warnings, formatId);
    storages.push({
      formatId,
      size: storageSize,
      magic,
      truncated,
      properties
    });
    if (storageSize === 0) break;
    cursor = storageEnd;
  }
  return { storages };
};

export { parsePropertyStore };
