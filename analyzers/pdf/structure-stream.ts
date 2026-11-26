import type { FileRangeReader } from "../file-range-reader.js";
import { readPdfText } from "./object.js";
import type { PdfIndirectDictionary } from "./object.js";
import { readArray, readName, skipTrivia, unsigned } from "./syntax.js";

// Bound both stored and inflated structural streams. Page content is never decoded here.
export const STREAM_LIMIT = 8 * 1024 * 1024;

const inflate = async (bytes: Uint8Array, limit: number): Promise<Uint8Array> => {
  const input = new Blob([Uint8Array.from(bytes).buffer]).stream();
  const reader = input.pipeThrough(new DecompressionStream("deflate")).getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    length += chunk.value.length;
    if (length > limit) {
      await reader.cancel();
      throw new Error("decoded stream exceeds the byte limit");
    }
    chunks.push(chunk.value);
  }
  const result = new Uint8Array(length);
  let position = 0;
  for (const chunk of chunks) {
    result.set(chunk, position);
    position += chunk.length;
  }
  return result;
};

const streamBytes = async (
  reader: FileRangeReader, object: PdfIndirectDictionary
): Promise<Uint8Array> => {
  // ISO 32000-2, 7.3.8.1: stream data starts after LF or CRLF and uses /Length bytes.
  const marker = /^stream\r?\n/.exec(object.following);
  const length = unsigned(object.dictionary.fields.get("Length"));
  if (!marker || length == null) throw new Error("missing stream marker or direct /Length");
  if (length > STREAM_LIMIT) throw new Error("stored stream exceeds the byte limit");
  const start = object.nextOffset + marker[0].length;
  if (length > reader.size - start) throw new Error("stream /Length extends beyond the file");
  const suffix = await readPdfText(reader, start + length, 64);
  const markerEnd = /^(?:\r\n?|\n)?endstream(?=[\0\t\n\f\r %])/.exec(suffix)?.[0].length;
  if (markerEnd == null || !/^endobj(?:[\0\t\n\f\r %]|$)/.test(
    suffix.slice(skipTrivia(suffix, markerEnd))
  )) {
    throw new Error("stream /Length does not lead to endstream and endobj");
  }
  return reader.readBytes(start, length);
};

const readFilter = (filter: string | undefined): string | null => {
  if (filter == null || filter === "null") return null;
  const filters = filter.startsWith("[") ? readArray(filter) : [filter];
  if (filters?.length !== 1) throw new Error("unsupported filter chain");
  const token = filters[0]!;
  if (readName(token) !== "FlateDecode") {
    throw new Error("unsupported filter " + token.slice(0, 80));
  }
  return token;
};

const readParameters = (parameters: string | undefined): string | undefined => {
  const array = readArray(parameters);
  if (array && array.length !== 1) throw new Error("invalid /DecodeParms array");
  return array ? array[0] : parameters;
};

export const decodeStructureStream = async (
  reader: FileRangeReader, object: PdfIndirectDictionary, limit: number
): Promise<{ bytes: Uint8Array; parameters: string | undefined }> => {
  const fields = object.dictionary.fields;
  const external = fields.get("F");
  if (external && external !== "null") throw new Error("external stream data is unsupported");
  const filter = readFilter(fields.get("Filter"));
  const parameters = readParameters(fields.get("DecodeParms"));
  const stored = await streamBytes(reader, object);
  if (filter) return { bytes: await inflate(stored, limit), parameters };
  if (stored.length > limit) throw new Error("stream exceeds the decoded byte limit");
  return { bytes: stored, parameters: undefined };
};
