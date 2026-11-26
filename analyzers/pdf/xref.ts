import type { FileRangeReader } from "../file-range-reader.js";
import { readIndirectDictionary, readPdfText } from "./object.js";
import { parseXrefStream } from "./xref-stream.js";
import { parseXrefTable, xrefKeyword } from "./xref-table.js";
import type { PdfRevision, PdfXref, PdfXrefEntry } from "./types.js";

// These budgets bound storage and seeks across the entire revision chain.
const ENTRY_LIMIT = 100_000;
const REVISION_LIMIT = 32;
// A classic xref row uses 20 bytes (ISO 32000-2, 7.5.4). Leave room for subsection
// headers and the trailer in addition to the rows.
const TABLE_WINDOW = 4 * 1024 * 1024;

const readXref = async (
  reader: FileRangeReader, offset: number, budget: number, issues: string[]
): Promise<PdfXref | null> => {
  if (offset < 0 || offset >= reader.size) {
    issues.push("Cross-reference offset " + offset + " points outside the file.");
    return null;
  }
  if (xrefKeyword.test(await readPdfText(reader, offset, 5))) {
    return parseXrefTable(await readPdfText(reader, offset, TABLE_WINDOW), offset, budget, issues);
  }
  const object = await readIndirectDictionary(reader, offset);
  const stream = object && await parseXrefStream(reader, object, offset, budget, issues);
  if (!stream) issues.push("Unable to read cross-reference information at offset " + offset + ".");
  return stream;
};

const readSupplement = async (
  reader: FileRangeReader, offset: number, budget: number, visited: Set<number>, issues: string[]
): Promise<PdfXref | null> => {
  if (visited.has(offset)) {
    issues.push("Cross-reference cycle at /XRefStm offset " + offset + ".");
    return null;
  }
  visited.add(offset);
  const object = await readIndirectDictionary(reader, offset);
  const stream = object && await parseXrefStream(reader, object, offset, budget, issues);
  if (!stream) issues.push("Unable to read /XRefStm at offset " + offset + ".");
  return stream;
};

const addEntries = (
  index: Map<number, PdfXrefEntry>, section: PdfXref, objectNumberLimit: number
): void => {
  // ISO 32000-2, 7.5.5: ignore entries beyond the object numbers declared by /Size.
  const limit = Math.min(objectNumberLimit, section.trailer?.size ?? Infinity);
  // Newest entries win, including free entries and unknown types that resolve to null.
  for (const entry of section.entries ?? []) {
    if (entry.objectNumber < limit && !index.has(entry.objectNumber)) {
      index.set(entry.objectNumber, entry);
    }
  }
};

const supplementOffset = (primary: PdfXref): number | null =>
  primary.kind === "table" ? primary.trailer?.xrefStreamOffset ?? null : null;

const readRevision = async (
  reader: FileRangeReader, offset: number, budget: number, visited: Set<number>, issues: string[]
): Promise<PdfRevision | null> => {
  if (visited.has(offset)) {
    issues.push("Cross-reference cycle at /Prev offset " + offset + ".");
    return null;
  }
  visited.add(offset);
  const primary = await readXref(reader, offset, budget, issues);
  if (!primary) return null;
  const extraOffset = supplementOffset(primary);
  if (extraOffset == null || !primary.entries) return { primary };
  const supplement = await readSupplement(reader, extraOffset,
    budget - primary.entries.length, visited, issues);
  return supplement ? { primary, supplement } : { primary };
};

const indexRevision = (
  index: Map<number, PdfXrefEntry>, { primary, supplement }: PdfRevision, size: number
): number => {
  addEntries(index, primary, size);
  // ISO 32000-1, 7.5.8.4: consult /XRefStm for entries absent from this table.
  if (supplement) addEntries(index, supplement, size);
  return (primary.entries?.length ?? 0) + (supplement?.entries?.length ?? 0);
};

const previousOffset = ({ primary, supplement }: PdfRevision): number | null => {
  // Unknown entries in a newer section can hide older objects. Stop at that boundary.
  if (!primary.entries || (supplementOffset(primary) != null && !supplement?.entries)) return null;
  return primary.trailer?.prev ?? null;
};

export const readRevisions = async (
  reader: FileRangeReader, start: number | null, issues: string[]
): Promise<{ revisions: PdfRevision[]; index: ReadonlyMap<number, PdfXrefEntry> }> => {
  const revisions: PdfRevision[] = [];
  const index = new Map<number, PdfXrefEntry>();
  const visited = new Set<number>();
  let offset = start;
  let budget = ENTRY_LIMIT;
  while (offset != null && revisions.length < REVISION_LIMIT) {
    const revision = await readRevision(reader, offset, budget, visited, issues);
    if (!revision) break;
    revisions.push(revision);
    budget -= indexRevision(index, revision, revisions[0]!.primary.trailer?.size ?? Infinity);
    offset = previousOffset(revision);
  }
  if (offset != null && revisions.length === REVISION_LIMIT) {
    issues.push("Cross-reference revision limit reached.");
  }
  return { revisions, index };
};
