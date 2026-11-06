import { createFileRangeReader } from "../file-range-reader.js";
import { decompressLzmaWithPropertiesTracked } from "../lzma/decoder.js";
import type { SwfParseResult } from "./types.js";

export const openZwsBody = async (file: File, start: number, end: number, header: SwfParseResult) => {
  if (!header.lzma) throw new Error("SWF LZMA properties are unavailable.");
  // ZWS: fixed header (8), compressed length (4), LZMA properties (5), raw LZMA stream.
  // https://github.com/ruffle-rs/ruffle/blob/master/swf/src/read.rs#L193
  // The existing SDK accepts complete buffers; load/decode in the background body phase.
  const source = createFileRangeReader(file, start + 17, end - start - 17);
  const packed = await source.readBytes(0, source.size);
  const decodedLzma = await decompressLzmaWithPropertiesTracked(
    header.lzma.properties, packed, BigInt(header.fileLength - 8));
  // Flash requires the end marker; Ruffle's make_lzma_reader documents this player behavior.
  if (decodedLzma.status !== 1 || decodedLzma.consumedPackedBytes !== packed.length) {
    throw new Error("SWF LZMA end marker or complete input consumption could not be confirmed.");
  }
  const decoded = new File([file.slice(start, start + 8), new Uint8Array(decodedLzma.bytes).buffer], "swf-body");
  return { ...createFileRangeReader(decoded, 0, decoded.size),
    finish: (): Promise<void> => Promise.resolve(), close: (): Promise<void> => Promise.resolve() };
};
