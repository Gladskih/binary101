import type { FileRangeReader } from "../file-range-reader.js";
import { parseTrailerDictionary } from "./dictionary.js";
import type { PdfIndirectDictionary } from "./object.js";
import { decodeStructureStream, STREAM_LIMIT } from "./structure-stream.js";
import { readIntegerArray, readName } from "./syntax.js";
import { readXrefPredictor, undoXrefPredictor } from "./xref-predictor.js";
import type { PdfXref, PdfXrefEntry, PdfXrefSection } from "./types.js";

const ranges = (raw: string | undefined, size: number): PdfXrefSection[] => {
  const index = raw == null ? [0, size] : readIntegerArray(raw);
  if (!index?.length || index.length % 2) throw new Error("invalid /Index array");
  const sections: PdfXrefSection[] = [];
  let end = 0;
  // ISO 32000-2, Table 17: /Index pairs are sorted by increasing object number.
  for (let i = 0; i < index.length; i += 2) {
    const start = index[i]!;
    const count = index[i + 1]!;
    if (start < end || count > size - start) throw new Error("overlapping or out-of-range /Index");
    sections.push({ start, count });
    end = start + count;
  }
  return sections;
};

const decodeField = (bytes: Uint8Array, offset: number, width: number): number => {
  let value = 0;
  for (let i = 0; i < width; i += 1) {
    value = value * 256 + bytes[offset + i]!;
    if (!Number.isSafeInteger(value)) throw new Error("entry field exceeds the safe integer range");
  }
  return value;
};

const decodeEntry = (objectNumber: number, type: number, second: number, third: number): PdfXrefEntry => {
  // ISO 32000-2, Table 18: type 2 addresses an index within an object stream.
  switch (type) {
    case 0: return { objectNumber, kind: "free", nextFree: second, generation: third };
    case 1: return { objectNumber, kind: "direct", offset: second, generation: third };
    case 2: return { objectNumber, kind: "compressed", streamObject: second, index: third };
    default: return { objectNumber, kind: "unknown", type, second, third };
  }
};

const decodeEntries = (
  bytes: Uint8Array, sections: PdfXrefSection[], widths: number[]
): PdfXrefEntry[] => {
  const [typeWidth = 0, secondWidth = 0, thirdWidth = 0] = widths;
  const rowWidth = typeWidth + secondWidth + thirdWidth;
  const entries: PdfXrefEntry[] = [];
  let offset = 0;
  for (const { start, count } of sections) {
    for (let i = 0; i < count; i += 1) {
      entries.push(decodeEntry(start + i, typeWidth ? decodeField(bytes, offset, typeWidth) : 1,
        decodeField(bytes, offset + typeWidth, secondWidth),
        decodeField(bytes, offset + typeWidth + secondWidth, thirdWidth)));
      offset += rowWidth;
    }
  }
  return entries;
};

const readEntries = async (
  reader: FileRangeReader, object: PdfIndirectDictionary,
  sections: PdfXrefSection[], budget: number
): Promise<PdfXrefEntry[]> => {
  const fields = object.dictionary.fields;
  const widths = readIntegerArray(fields.get("W"));
  if (widths?.length !== 3) throw new Error("invalid /W field widths");
  const rowWidth = widths.reduce((sum, width) => sum + width, 0);
  const count = sections.reduce((sum, section) => sum + section.count, 0);
  if (count > budget) throw new Error("xref entry limit reached");
  if (!rowWidth) throw new Error("invalid zero-width row layout");
  if (rowWidth > STREAM_LIMIT || count * rowWidth > STREAM_LIMIT) {
    throw new Error("declared row layout exceeds the byte limit");
  }
  const { bytes, parameters } = await decodeStructureStream(reader, object, STREAM_LIMIT);
  const size = count * rowWidth;
  return decodeEntries(undoXrefPredictor(bytes, readXrefPredictor(parameters, rowWidth), size),
    sections, widths);
};

export const parseXrefStream = async (
  reader: FileRangeReader, object: PdfIndirectDictionary, offset: number,
  budget: number, issues: string[]
): Promise<PdfXref | null> => {
  if (readName(object.dictionary.fields.get("Type")) !== "XRef") return null;
  const trailer = parseTrailerDictionary(object.dictionary, issues);
  let sections: PdfXrefSection[] = [];
  let entries: PdfXrefEntry[] | null = null;
  try {
    if (!trailer.size) throw new Error("missing or invalid /Size");
    sections = ranges(object.dictionary.fields.get("Index"), trailer.size);
    entries = await readEntries(reader, object, sections, budget);
  } catch (error) {
    issues.push("Cross-reference stream at " + offset + ": " +
      (error instanceof Error ? error.message : String(error)) + ".");
  }
  return { kind: "stream", offset, object: object.ref, sections, entries, trailer };
};
