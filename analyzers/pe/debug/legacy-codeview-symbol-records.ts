import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readLegacyCodeViewSymbolText, type LegacyCodeViewSymbolText } from "./legacy-codeview-symbol-text.js";

export interface LegacyCodeViewSymbol extends LegacyCodeViewSymbolText {
  type: number;
  children?: LegacyCodeViewSymbol[];
  discarded?: { reason: number; fileId: number; line: number };
}
interface LegacyCodeViewSymbolStream {
  kind: "symbols" | "entryThis" | "discarded";
  start: number;
  end: number;
  records: LegacyCodeViewSymbol[];
}

const discardedInfo = (reader: LegacyCodeViewReader, fields: DataView) => {
  const flags = fields.getUint32(4, true);
  if (flags >>> 8) reader.warn("CodeView discarded-symbol reserved bits are nonzero.");
  if ((flags & 255) > 2) reader.warn("CodeView discarded-symbol reason is unknown.");
  return { reason: flags & 255, fileId: fields.getUint32(8, true), line: fields.getUint32(12, true) };
};

const embeddedStreams = async (reader: LegacyCodeViewReader, record: LegacyCodeViewSymbol,
  start: number, end: number): Promise<LegacyCodeViewSymbolStream[]> => {
  if (record.type !== 0xe && record.type !== 0x113b) return [];
  // TIS 2.2 S_ENTRYTHIS encloses one complete symbol; DISCARDEDSYM encloses
  // original records after its 16-byte fixed prefix (including reclen/rectyp).
  // https://openwatcom.org/ftp/devel/docs/CodeView.pdf
  // https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L4538
  const prefix = record.type === 0xe ? 4 : 16;
  if (prefix > end - start) throw new Error("CodeView embedded symbol header exceeds record bounds.");
  if (record.type === 0x113b) record.discarded = discardedInfo(reader, await reader.view(start, prefix));
  record.children = [];
  return [{ kind: record.type === 0xe ? "entryThis" : "discarded",
    start: start + prefix, end, records: record.children }];
};

const appendRecord = async (reader: LegacyCodeViewReader, stream: LegacyCodeViewSymbolStream,
  pending: LegacyCodeViewSymbolStream[], offset: number): Promise<number> => {
  if (stream.end - offset < 4) throw new Error("CodeView symbol header exceeds stream bounds.");
  const length = await reader.uint16(offset);
  if (length < 2 || length + 2 > stream.end - offset) throw new Error("Invalid CodeView symbol record length.");
  const type = await reader.uint16(offset + 2);
  const record: LegacyCodeViewSymbol = { type };
  stream.records.push(record);
  try {
    Object.assign(record, await readLegacyCodeViewSymbolText(reader.subsection(offset, length + 2), type));
    pending.push(...await embeddedStreams(reader, record, offset, offset + length + 2));
  } catch (error) { reader.warn(`CodeView symbol ${type}: ${String(error)}`); }
  return offset + length + 2;
};

const drainStreams = async (reader: LegacyCodeViewReader, pending: LegacyCodeViewSymbolStream[]): Promise<void> => {
  while (pending.length) {
    const stream = pending.pop()!;
    for (let offset = stream.start; offset < stream.end;) {
      try { offset = await appendRecord(reader, stream, pending, offset); }
      catch (error) { reader.warn(String(error)); break; }
    }
    if (stream.kind === "entryThis" && stream.records.length !== 1) {
      reader.warn("CodeView entry-this must contain exactly one symbol record.");
    }
  }
};

/** Iterative traversal keeps nesting bounded by actual record bytes, without a depth heuristic. */
export const readLegacyCodeViewSymbolRecords = async (
  reader: LegacyCodeViewReader, start: number, end: number
): Promise<LegacyCodeViewSymbol[]> => {
  const records: LegacyCodeViewSymbol[] = [];
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || end > reader.size) {
    reader.warn("CodeView symbol stream bounds exceeded.");
    return records;
  }
  await drainStreams(reader, [{ kind: "symbols", start, end, records }]);
  return records;
};

/** A type leaf holds exactly one length-delimited symbol, followed by possible type padding. */
export const readLegacyCodeViewEmbeddedSymbol = async (
  reader: LegacyCodeViewReader, start: number
): Promise<LegacyCodeViewSymbol[]> => {
  const records: LegacyCodeViewSymbol[] = [];
  const pending: LegacyCodeViewSymbolStream[] = [];
  try { await appendRecord(reader, { kind: "symbols", start, end: reader.size, records }, pending, start); }
  catch (error) { reader.warn(`CodeView embedded symbol: ${String(error)}`); }
  await drainStreams(reader, pending);
  return records;
};
