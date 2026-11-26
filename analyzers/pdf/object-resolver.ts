import type { FileRangeReader } from "../file-range-reader.js";
import { decodePdfBytes, DICTIONARY_WINDOW, readIndirectDictionary } from "./object.js";
import { readObjectStream } from "./object-stream.js";
import { readDictionary, skipTrivia } from "./syntax.js";
import type { PdfDictionary } from "./syntax.js";
import type { PdfIndirectRef, PdfXrefEntry } from "./types.js";

const directObject = async (
  reader: FileRangeReader, entry: Extract<PdfXrefEntry, { kind: "direct" }>
) => {
  if (entry.offset < 0 || entry.offset >= reader.size) throw new Error("offset is outside the file");
  const object = await readIndirectDictionary(reader, entry.offset);
  if (!object || object.ref.objectNumber !== entry.objectNumber ||
      object.ref.generation !== entry.generation) {
    throw new Error("invalid or mismatched indirect object header or dictionary");
  }
  return object;
};

const objectStreamCache = (
  reader: FileRangeReader, index: ReadonlyMap<number, PdfXrefEntry>
) => {
  // Only the catalog, page tree root and Info are resolved. Share their decoded object streams.
  const streams = new Map<number, ReturnType<typeof readObjectStream>>();
  // Retain decoded streams so a tree walk can reuse them without repeatedly inflating input.
  const byteBudget = 32 * 1024 * 1024;
  let decodedBytes = 0;
  const load = async (number: number) => {
    const entry = index.get(number);
    if (entry?.kind !== "direct" || entry.generation !== 0) {
      throw new Error("missing generation-zero object stream");
    }
    if (decodedBytes >= byteBudget) throw new Error("decoded object stream budget reached");
    const stream = await readObjectStream(reader, await directObject(reader, entry));
    decodedBytes += stream.body.buffer.byteLength;
    if (decodedBytes > byteBudget) throw new Error("decoded object stream budget reached");
    return stream;
  };
  return (number: number): ReturnType<typeof readObjectStream> => {
    const existing = streams.get(number);
    if (existing) return existing;
    const stream = load(number);
    streams.set(number, stream);
    return stream;
  };
};

const compressedDictionary = async (
  loadStream: ReturnType<typeof objectStreamCache>, entry: Extract<PdfXrefEntry, { kind: "compressed" }>
): Promise<PdfDictionary> => {
  const { body, entries } = await loadStream(entry.streamObject);
  const item = entries[entry.index];
  if (item?.objectNumber !== entry.objectNumber) throw new Error("mismatched object stream index");
  const end = entries[entry.index + 1]?.offset ?? body.length;
  if (end - item.offset > DICTIONARY_WINDOW) throw new Error("compressed dictionary exceeds the byte limit");
  const text = decodePdfBytes(body.subarray(item.offset, end));
  const dictionary = readDictionary(text);
  if (!dictionary || skipTrivia(text, dictionary.end) !== text.length) {
    throw new Error("invalid compressed dictionary");
  }
  return dictionary;
};

const findEntry = (index: ReadonlyMap<number, PdfXrefEntry>, ref: PdfIndirectRef) => {
  const entry = index.get(ref.objectNumber);
  if (!entry) throw new Error("cross-reference entry is unavailable");
  if (entry.kind === "free") throw new Error("cross-reference entry is free");
  if (entry.kind === "unknown") throw new Error("unknown cross-reference entry type");
  if ((entry.kind === "compressed" ? 0 : entry.generation) !== ref.generation) {
    throw new Error("cross-reference generation does not match");
  }
  return entry;
};

export interface PdfObjectResolver {
  dictionary: (ref: PdfIndirectRef, label: string) => Promise<PdfDictionary | null>;
  streamDictionary: (ref: PdfIndirectRef, label: string) => Promise<PdfDictionary | null>;
}

const warn = (issues: string[], ref: PdfIndirectRef, label: string, error: unknown): null => {
  issues.push(label + " " + ref.objectNumber + " " + ref.generation + " R: " +
    (error instanceof Error ? error.message : String(error)) + ".");
  return null;
};

export const createObjectResolver = (
  reader: FileRangeReader, index: ReadonlyMap<number, PdfXrefEntry>,
  encryption: string | null, issues: string[]
): PdfObjectResolver => {
  const loadStream = objectStreamCache(reader, index);
  const dictionary = async (ref: PdfIndirectRef, label: string): Promise<PdfDictionary | null> => {
    try {
      const entry = findEntry(index, ref);
      if (entry.kind === "compressed") {
        if (encryption != null) throw new Error("object stream belongs to an encrypted PDF");
        return await compressedDictionary(loadStream, entry);
      }
      const object = await directObject(reader, entry);
      if (!/^endobj(?:[\0\t\n\f\r %]|$)/.test(object.following)) {
        throw new Error("dictionary does not terminate with endobj");
      }
      return object.dictionary;
    } catch (error) {
      return warn(issues, ref, label, error);
    }
  };
  const streamDictionary = async (ref: PdfIndirectRef, label: string): Promise<PdfDictionary | null> => {
    try {
      const entry = findEntry(index, ref);
      if (entry.kind !== "direct") throw new Error("stream must be a direct xref entry");
      const object = await directObject(reader, entry);
      if (!/^stream\r?\n/.test(object.following)) throw new Error("expected a stream");
      return object.dictionary;
    } catch (error) {
      return warn(issues, ref, label, error);
    }
  };
  return { dictionary, streamDictionary };
};
