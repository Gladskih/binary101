import { decompressLzmaWithProperties, decompressLzma2WithProperty } from "../lzma/decoder.js";
import { SEVENZIP_LZMA_METHOD_ID, SEVENZIP_LZMA2_METHOD_ID } from "./method-ids.js";

export const isLzmaMethod = (methodId: string): boolean =>
  methodId === SEVENZIP_LZMA_METHOD_ID || methodId === SEVENZIP_LZMA2_METHOD_ID;

export const getLzmaCoderError = (
  methodId: string, properties: number[] | undefined
): string | undefined => {
  if (!isLzmaMethod(methodId)) return "7z extraction supports single LZMA or LZMA2 folders.";
  if (methodId === SEVENZIP_LZMA_METHOD_ID) {
    if (properties?.length !== 5) return "LZMA coder properties are invalid.";
  } else if (properties?.length !== 1 || !Number.isInteger(properties[0]) ||
    properties[0]! < 0 || properties[0]! > 40) {
    // C/Lzma2Dec.c: one dictionary property, 0..40 (40 means UINT32_MAX).
    // https://github.com/ip7z/7zip/blob/b88c6bc09339de32f7d18bbab900686b244f42ba/C/Lzma2Dec.c
    return "LZMA2 coder properties are invalid.";
  }
  return undefined;
};

export const decodeLzmaCoder = async (
  methodId: string, properties: number[], packed: Uint8Array, size: bigint
): Promise<Uint8Array> => {
  const error = getLzmaCoderError(methodId, properties);
  if (error) throw new Error(error);
  return methodId === SEVENZIP_LZMA2_METHOD_ID
    ? decompressLzma2WithProperty(properties[0]!, packed, size)
    : decompressLzmaWithProperties(properties, packed, size);
};
