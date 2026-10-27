import type { DecodeResult, Decoder } from "lzma-sdk-decode";
import { loadLzmaDecoder } from "#lzma-decoder-loader";

export interface TrackedLzmaResult {
  bytes: Uint8Array;
  consumedPackedBytes: number;
  status: number;
}

const validateUnpackSize = (unpackSize: bigint): void => {
  // The decoder exposes wasm32 addresses; its allocator checks the complete working range.
  if (unpackSize < 0n || unpackSize > 0xffff_ffffn) {
    throw new Error("LZMA unpack size exceeds supported range.");
  }
};

const validateProperties = (properties: number[], unpackSize: bigint): void => {
  // LZMA_PROPS_SIZE in the pinned SDK's C/LzmaDec.h is five bytes.
  // https://github.com/ip7z/7zip/blob/b88c6bc09339de32f7d18bbab900686b244f42ba/C/LzmaDec.h
  if (properties.length !== 5) throw new Error("LZMA coder properties must be exactly 5 bytes.");
  for (const property of properties) {
    if (!Number.isInteger(property) || property < 0 || property > 255) {
      throw new Error("LZMA coder properties must contain byte values.");
    }
  }
  validateUnpackSize(unpackSize);
};

const checkedResult = (result: DecodeResult, size: number): TrackedLzmaResult => {
  if (result.resultCode !== 0) throw new Error(`LZMA SDK error ${result.resultCode}.`);
  // ELzmaStatus: FINISHED_WITH_MARK=1, MAYBE_FINISHED_WITHOUT_MARK=4.
  // https://github.com/ip7z/7zip/blob/b88c6bc09339de32f7d18bbab900686b244f42ba/C/LzmaDec.h
  if (result.status !== 1 && result.status !== 4) {
    throw new Error(`LZMA completion status ${result.status} is incomplete.`);
  }
  if (result.data.byteLength !== size) throw new Error("LZMA output size does not match declared size.");
  return { bytes: result.data, consumedPackedBytes: result.bytesRead, status: result.status };
};

const createRuntime = (load: () => Promise<Decoder>) => {
  let decoder: Promise<Decoder> | undefined;
  return async (decode: (native: Decoder) => DecodeResult): Promise<DecodeResult> => {
    try {
      decoder ??= load();
      return decode(await decoder);
    } catch (error) {
      // Retry initialization on the next file; a trapped SDK instance is quarantined.
      decoder = undefined;
      throw error;
    }
  };
};

const createLzmaDecode = (run: ReturnType<typeof createRuntime>) =>
  async (properties: number[], packed: Uint8Array, size: bigint): Promise<TrackedLzmaResult> => {
    validateProperties(properties, size);
    return checkedResult(await run(native =>
      native.decodeLzma(packed, Uint8Array.from(properties), Number(size))), Number(size));
  };

const createLzma2Decode = (run: ReturnType<typeof createRuntime>) =>
  async (property: number, packed: Uint8Array, size: bigint): Promise<TrackedLzmaResult> => {
    // Lzma2Dec_GetOldProps accepts one dictionary property in the range 0..40.
    // https://github.com/ip7z/7zip/blob/b88c6bc09339de32f7d18bbab900686b244f42ba/C/Lzma2Dec.c
    if (!Number.isInteger(property) || property < 0 || property > 40) {
      throw new Error("LZMA2 dictionary property is invalid.");
    }
    validateUnpackSize(size);
    const result = await run(native => native.decodeLzma2(packed, property, Number(size)));
    const decoded = checkedResult(result, Number(size));
    if (result.status !== 1) throw new Error("LZMA2 stream has no end marker.");
    return decoded;
  };

export const createLzmaDecompressor = (load: () => Promise<Decoder> = loadLzmaDecoder) =>
  createLzmaDecode(createRuntime(load));

export const createLzma2Decompressor = (load: () => Promise<Decoder> = loadLzmaDecoder) =>
  createLzma2Decode(createRuntime(load));

const runtime = createRuntime(loadLzmaDecoder);
export const decompressLzmaWithPropertiesTracked = createLzmaDecode(runtime);
const decompressLzma2Tracked = createLzma2Decode(runtime);

const completeInput = (result: TrackedLzmaResult, size: number): Uint8Array => {
  if (result.consumedPackedBytes !== size) throw new Error("LZMA stream has unconsumed input.");
  return result.bytes;
};

export const decompressLzmaWithProperties = async (
  properties: number[], packed: Uint8Array, size: bigint
): Promise<Uint8Array> => {
  return completeInput(await decompressLzmaWithPropertiesTracked(properties, packed, size),
    packed.byteLength);
};

export const decompressLzma2WithProperty = async (
  property: number, packed: Uint8Array, size: bigint
): Promise<Uint8Array> =>
  completeInput(await decompressLzma2Tracked(property, packed, size), packed.byteLength);
