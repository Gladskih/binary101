"use strict";

import type { MsvcRttiImage } from "./image.js";
import {
  MAX_TYPE_DESCRIPTOR_NAME_BYTES,
  TYPE_DESCRIPTOR_FIXED_SIZE
} from "./layout.js";
import type { MsvcRttiTypeDescriptor } from "./types.js";

const hasSupportedDecoratedName = (value: string): boolean => {
  if (!(value.startsWith(".?AV") || value.startsWith(".?AU"))) return false;
  if (!value.endsWith("@@") || value.length <= 6) return false;
  for (let index = 0; index < value.length; index += 1) {
    const byte = value.charCodeAt(index);
    if (byte < 0x21 || byte > 0x7e) return false;
  }
  return true;
};

const decodeDecoratedName = (bytes: Uint8Array): string | null => {
  const terminator = bytes.indexOf(0);
  if (terminator < 0 || terminator > MAX_TYPE_DESCRIPTOR_NAME_BYTES) return null;
  let value = "";
  for (let index = 0; index < terminator; index += 1) value += String.fromCharCode(bytes[index]!);
  return hasSupportedDecoratedName(value) ? value : null;
};

export const parseMsvcRttiTypeDescriptor = async (
  image: MsvcRttiImage,
  rva: number
): Promise<MsvcRttiTypeDescriptor | null> => {
  const fixed = await image.readData(rva, TYPE_DESCRIPTOR_FIXED_SIZE, BigUint64Array.BYTES_PER_ELEMENT);
  if (!fixed || fixed.getBigUint64(8, true) !== 0n) return null;
  const nameRva = rva + TYPE_DESCRIPTOR_FIXED_SIZE;
  const available = image.availableDataSize(nameRva, MAX_TYPE_DESCRIPTOR_NAME_BYTES + 1);
  if (!available) return null;
  const nameView = await image.readData(nameRva, available, Uint8Array.BYTES_PER_ELEMENT);
  if (!nameView) return null;
  const decoratedName = decodeDecoratedName(
    new Uint8Array(nameView.buffer, nameView.byteOffset, nameView.byteLength)
  );
  return decoratedName ? { rva, decoratedName } : null;
};

