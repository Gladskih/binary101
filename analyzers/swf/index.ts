import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import { readSwfHeader, readSwfMovieHeader, readSwfLzmaHeader } from "./header.js";
import { openCwsBody, openCwsPrefix } from "./source.js";
import { openZwsBody } from "./lzma-source.js";
import { readFirstSwfAttributes, readSwfTags } from "./tags.js";
import type { SwfParseResult } from "./types.js";

const isSwfRange = (file: File, start: number, end: number): boolean =>
  Number.isSafeInteger(start) && Number.isSafeInteger(end) && start >= 0 && end <= file.size && end - start >= 8;

const readMovie = async (reader: FileRangeReader, result: SwfParseResult): Promise<number> => {
  const prefix = await reader.read(8, 1);
  if (!prefix.byteLength) throw new Error("SWF movie header is truncated.");
  const length = Math.ceil((5 + 4 * (prefix.getUint8(0) >>> 3)) / 8) + 4;
  const movie = readSwfMovieHeader(await reader.read(8, length));
  result.movie = movie.movie;
  if (movie.movie.xMax < movie.movie.xMin || movie.movie.yMax < movie.movie.yMin) {
    result.issues.push("SWF RECT has reversed coordinates.");
  }
  return movie.tagsOffset;
};

const recordFailure = (result: SwfParseResult, error: unknown): SwfParseResult => {
  result.issues.push(error instanceof Error ? error.message : "SWF structure could not be read.");
  return result;
};

export const analyzeSwfBody = async (
  file: File, start: number, end: number, header: SwfParseResult
): Promise<SwfParseResult> => {
  const result: SwfParseResult = { signature: header.signature, version: header.version,
    fileLength: header.fileLength, ...(header.lzma ? { lzma: header.lzma } : {}), issues: [] };
  if (!isSwfRange(file, start, end) || header.signature === "FWS") {
    return recordFailure(result, new Error("Compressed SWF body range or signature is invalid."));
  }
  let body: Awaited<ReturnType<typeof openZwsBody>> | ReturnType<typeof openCwsBody> | null = null;
  try {
    body = header.signature === "ZWS" ? await openZwsBody(file, start, end, header)
      : openCwsBody(file, start, end, header.fileLength);
    const offset = await readMovie(body, result);
    await readSwfTags(body, offset, result);
    await body.finish(); // zlib end/checksum and actual decompressed length validation.
    return result;
  } catch (error) {
    return recordFailure(result, error);
  } finally {
    await body?.close();
  }
};

export const parseSwfRange = async (
  file: File, start: number, end: number
): Promise<SwfParseResult | null> => {
  if (!isSwfRange(file, start, end)) return null;
  const physical = createFileRangeReader(file, start, end - start);
  const header = readSwfHeader(await physical.read(0, 8));
  if (!header) return null;
  const result: SwfParseResult = { ...header, issues: [] };
  try {
    if (header.signature === "ZWS") {
      result.lzma = readSwfLzmaHeader(await physical.read(0, 17), physical.size);
      return result;
    }
    if (header.signature === "CWS" && header.version < 6) throw new Error("CWS requires SWF 6 or later.");
    if (header.signature === "CWS") {
      const body = openCwsPrefix(file, start, end, header.fileLength);
      try {
        await readFirstSwfAttributes(body, await readMovie(body, result), result);
      } finally { await body.close(); }
    } else {
      if (physical.size !== header.fileLength) throw new Error("Uncompressed SWF length differs from FileLength.");
      await readSwfTags(physical, await readMovie(physical, result), result);
    }
  } catch (error) {
    recordFailure(result, error);
  }
  return result;
};

export const parseSwf = async (file: File, prefix?: DataView): Promise<SwfParseResult | null> => {
  if (prefix && !readSwfHeader(prefix)) return null;
  return parseSwfRange(file, 0, file.size).catch(() => null);
};
