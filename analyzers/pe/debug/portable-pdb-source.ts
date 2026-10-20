import { createMemoryRangeReader } from "../../memory-range-reader.js";
import { DEFAULT_FILE_READ_WINDOW_BYTES, type FileRangeReader } from "../../file-range-reader.js";
import { inflateEmbeddedDebugImage } from "./embedded-debug-image.js";

export interface PortablePdbSource {
  storage: "raw" | "deflate";
  bytes: number;
  lines: number | null;
  encoding: string | null;
}

const sourceEncoding = (prefix: Uint8Array): string => {
  // Source blobs contain the original file bytes, including an optional Unicode BOM.
  // An absent BOM does not establish a legacy code page: only valid UTF-8 is accepted.
  // Unicode BOM byte patterns: https://www.unicode.org/faq/utf_bom.html
  const view = new DataView(prefix.buffer, prefix.byteOffset, prefix.length);
  const bom32 = prefix.length >= 4 ? view.getUint32(0) : 0;
  if (bom32 === 0xfffe0000) return "UTF-32LE";
  if (bom32 === 0x0000feff) return "UTF-32BE";
  const bom16 = prefix.length >= 2 ? view.getUint16(0) : 0;
  if (bom16 === 0xfffe) return "UTF-16LE";
  if (bom16 === 0xfeff) return "UTF-16BE";
  return "UTF-8";
};

const validUnicodeScalar = (code: number): boolean =>
  code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff);

const utf32LineCount = async (reader: FileRangeReader, encoding: string): Promise<number> => {
  if (reader.size % 4) throw new Error("partial UTF-32 code unit");
  let lines = 0;
  let previousCR = false;
  for (let offset = 4; offset < reader.size; offset += DEFAULT_FILE_READ_WINDOW_BYTES) {
    const view = await reader.read(offset, Math.min(DEFAULT_FILE_READ_WINDOW_BYTES, reader.size - offset));
    for (let index = 0; index < view.byteLength; index += 4) {
      const code = view.getUint32(index, encoding === "UTF-32LE");
      if (!validUnicodeScalar(code)) throw new Error("invalid UTF-32 scalar value");
      if (!lines) lines = 1;
      if (code === 13 || (code === 10 && !previousCR)) lines++;
      previousCR = code === 13;
    }
  }
  return lines;
};

const countTextLines = (text: string, state: { lines: number; hasText: boolean; previousCR: boolean }): void => {
  if (!text.length) return;
  if (!state.hasText) state.lines = 1;
  state.lines += (text.match(/\r\n|\r|\n/g) ?? []).length;
  if (state.previousCR && text.startsWith("\n")) state.lines--;
  state.hasText = true;
  state.previousCR = text.endsWith("\r");
};

const sourceTextStatistics = async (reader: FileRangeReader) => {
  const encoding = sourceEncoding(await reader.readBytes(0, Math.min(4, reader.size)));
  if (encoding.startsWith("UTF-32")) return { lines: await utf32LineCount(reader, encoding), encoding };
  const decoder = new TextDecoder(encoding, { fatal: true });
  const state = { lines: 0, hasText: false, previousCR: false };
  for (let offset = 0; offset < reader.size; offset += DEFAULT_FILE_READ_WINDOW_BYTES) {
    const bytes = await reader.readBytes(offset, Math.min(DEFAULT_FILE_READ_WINDOW_BYTES, reader.size - offset));
    countTextLines(decoder.decode(bytes, { stream: true }), state);
  }
  countTextLines(decoder.decode(), state);
  return { lines: state.lines, encoding };
};

const analyzeSourceText = async (reader: FileRangeReader, issues: string[]) => {
  try {
    return await sourceTextStatistics(reader);
  } catch {
    issues.push("Portable PDB embedded source encoding is unknown or invalid; text statistics are unavailable.");
    return { lines: null, encoding: null };
  }
};

export const analyzePortablePdbSource = async (
  bytes: Uint8Array, issues: string[]
): Promise<PortablePdbSource | null> => {
  // EmbeddedSource format: int32 size (zero = raw, positive = raw Deflate).
  // https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md#embedded-source-c-and-vb-compilers
  if (bytes.length < 4) {
    issues.push("Portable PDB embedded source header is truncated.");
    return null;
  }
  const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.length).getInt32(0, true);
  if (size < 0) {
    issues.push("Portable PDB embedded source uses a reserved future format.");
    return null;
  }
  try {
    const content = createMemoryRangeReader(bytes.subarray(4));
    const reader = size ? await inflateEmbeddedDebugImage(content, size) : content;
    return { storage: size ? "deflate" : "raw", bytes: reader.size,
      ...await analyzeSourceText(reader, issues) };
  } catch (error) {
    issues.push(`Portable PDB embedded source decompression failed: ${(error as Error).message}.`);
    return null;
  }
};
