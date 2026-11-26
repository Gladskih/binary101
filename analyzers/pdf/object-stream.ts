import type { FileRangeReader } from "../file-range-reader.js";
import { decodePdfBytes } from "./object.js";
import type { PdfIndirectDictionary } from "./object.js";
import { decodeStructureStream, STREAM_LIMIT } from "./structure-stream.js";
import { readDictionary, readName, skipTrivia, unsigned } from "./syntax.js";

interface ObjectStreamEntry {
  objectNumber: number;
  offset: number;
}

const integer = /\d+(?=[\0\t\n\f\r %]|$)/y;

const readInteger = (text: string, position: number): number | null => {
  integer.lastIndex = position;
  return unsigned(integer.exec(text)?.[0]);
};

const readHeader = (text: string, count: number, bodySize: number): ObjectStreamEntry[] => {
  const entries: ObjectStreamEntry[] = [];
  const seen = new Set<number>();
  let position = skipTrivia(text, 0);
  let previous = -1;
  for (let i = 0; i < count; i += 1) {
    const objectNumber = readInteger(text, position);
    if (!objectNumber || seen.has(objectNumber)) throw new Error("invalid object stream number");
    const offset = readInteger(text, skipTrivia(text, integer.lastIndex));
    if (offset == null || offset >= bodySize || offset <= previous || (i === 0 && offset !== 0)) {
      throw new Error("invalid object stream offset");
    }
    entries.push({ objectNumber, offset });
    seen.add(objectNumber);
    previous = offset;
    position = skipTrivia(text, integer.lastIndex);
  }
  return entries;
};

const checkDecodeParameters = (parameters: string | undefined): void => {
  if (parameters == null || parameters === "null") return;
  const dictionary = readDictionary(parameters);
  if (!dictionary || unsigned(dictionary.fields.get("Predictor") ?? "1") !== 1) {
    throw new Error("unsupported object stream /DecodeParms");
  }
};

export const readObjectStream = async (
  reader: FileRangeReader, object: PdfIndirectDictionary
): Promise<{ body: Uint8Array; entries: ObjectStreamEntry[] }> => {
  const fields = object.dictionary.fields;
  if (readName(fields.get("Type")) !== "ObjStm") throw new Error("expected /Type /ObjStm");
  const count = unsigned(fields.get("N"));
  const first = unsigned(fields.get("First"));
  // ISO 32000-2, 7.5.7: /N pairs precede /First. Bound the header and object index.
  if (!count || !first || count > 20_000 || first > STREAM_LIMIT || count > first / 3) {
    throw new Error("invalid or oversized /N or /First");
  }
  const { bytes, parameters } = await decodeStructureStream(reader, object, STREAM_LIMIT);
  checkDecodeParameters(parameters);
  if (first >= bytes.length) throw new Error("/First lies outside the decoded object stream");
  const body = bytes.subarray(first);
  return {
    body,
    entries: readHeader(decodePdfBytes(bytes.subarray(0, first)), count, body.length)
  };
};
