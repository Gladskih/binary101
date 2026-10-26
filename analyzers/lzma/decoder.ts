import type { DecodeResult, Decoder } from "lzma-sdk-decode";
import { loadLzmaDecoder } from "#lzma-decoder-loader";

export interface TrackedLzmaResult {
  bytes: Uint8Array;
  consumedPackedBytes: number;
}

const validateProperties = (properties: number[], unpackSize: bigint): void => {
  // LZMA_PROPS_SIZE in the pinned SDK's C/LzmaDec.h is five bytes.
  // https://github.com/ip7z/7zip/blob/b88c6bc09339de32f7d18bbab900686b244f42ba/C/LzmaDec.h
  if (properties.length !== 5) throw new Error("LZMA coder properties must be exactly 5 bytes.");
  for (const property of properties) {
    if (!Number.isInteger(property) || property < 0 || property > 255) {
      throw new Error("LZMA coder properties must contain byte values.");
    }
  }
  // The decoder exposes wasm32 addresses; its allocator checks the complete working range.
  if (unpackSize < 0n || unpackSize > 0xffff_ffffn) {
    throw new Error("LZMA unpack size exceeds supported range.");
  }
};

const checkedResult = (result: DecodeResult, size: number): TrackedLzmaResult => {
  if (result.resultCode !== 0) throw new Error(`LZMA SDK error ${result.resultCode}.`);
  // ELzmaStatus: FINISHED_WITH_MARK=1, MAYBE_FINISHED_WITHOUT_MARK=4.
  // https://github.com/ip7z/7zip/blob/b88c6bc09339de32f7d18bbab900686b244f42ba/C/LzmaDec.h
  if (result.status !== 1 && result.status !== 4) {
    throw new Error(`LZMA completion status ${result.status} is incomplete.`);
  }
  if (result.data.byteLength !== size) throw new Error("LZMA output size does not match declared size.");
  return { bytes: result.data, consumedPackedBytes: result.bytesRead };
};

export const createLzmaDecompressor = (load: () => Promise<Decoder> = loadLzmaDecoder) => {
  let decoder: Promise<Decoder> | undefined;
  return async (properties: number[], packed: Uint8Array, size: bigint): Promise<TrackedLzmaResult> => {
    validateProperties(properties, size);
    let result: DecodeResult;
    try {
      decoder ??= load();
      result = (await decoder).decodeLzma(packed, Uint8Array.from(properties), Number(size));
    } catch (error) {
      // Retry initialization on the next file; a trapped SDK instance is quarantined.
      decoder = undefined;
      throw error;
    }
    return checkedResult(result, Number(size));
  };
};

export const decompressLzmaWithPropertiesTracked = createLzmaDecompressor();

export const decompressLzmaWithProperties = async (
  properties: number[], packed: Uint8Array, size: bigint
): Promise<Uint8Array> => {
  const result = await decompressLzmaWithPropertiesTracked(properties, packed, size);
  if (result.consumedPackedBytes !== packed.byteLength) {
    throw new Error("LZMA stream has unconsumed input.");
  }
  return result.bytes;
};
