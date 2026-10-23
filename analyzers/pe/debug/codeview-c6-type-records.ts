import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { LegacyCodeViewTypes } from "./legacy-codeview-type-records.js";

type TypeRecord = LegacyCodeViewTypes["records"][number];

// C6 leaves differ from C7: byte kind, byte linkage + WORD record length,
// immediate numeric leaves below 128, and 0x82-prefixed counted ANSI names.
// Microsoft C Developer's Toolkit, 1.4; Microsoft's type6.cpp/typeinfo.h.
// https://www.pcjs.org/documents/books/mspl13/c/ctoolkit/
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/type6.cpp
class TypeCursor {
  offset = 4;
  constructor(readonly reader: LegacyCodeViewReader) {}
  async byte(): Promise<number> { return (await this.reader.view(this.offset++, 1)).getUint8(0); }
  async peek(): Promise<number> { return (await this.reader.view(this.offset, 1)).getUint8(0); }
  async skip(size: number): Promise<void> { await this.reader.view(this.offset, size); this.offset += size; }
  async index(): Promise<void> {
    if (await this.byte() !== 131) throw new Error("Invalid C6 type index leaf.");
    await this.skip(2);
  }
  async name(): Promise<string> {
    if (await this.byte() !== 130) throw new Error("Invalid C6 string leaf.");
    const value = await this.reader.pascal(this.offset);
    this.offset = value.end;
    return value.name;
  }
  async numeric(): Promise<bigint> {
    const code = await this.byte();
    if (code < 128) return BigInt(code);
    const size = new Map([[133, 2], [134, 4], [135, 8], [136, 1], [137, 2], [138, 4], [139, 8]]).get(code);
    if (size === undefined) throw new Error(`Unknown C6 numeric leaf ${code}.`);
    const view = await this.reader.view(this.offset, size);
    this.offset += size;
    let value = 0n;
    for (let index = size - 1; index >= 0; index--) value = value * 256n + BigInt(view.getUint8(index));
    return code >= 136 && view.getUint8(size - 1) & 128 ? value - (1n << BigInt(size * 8)) : value;
  }
  async optionalName(record: TypeRecord): Promise<void> {
    if (this.offset < this.reader.size && await this.peek() === 130) record.name = await this.name();
  }
}

const readList = async (cursor: TypeCursor, record: TypeRecord): Promise<void> => {
  record.strings = [];
  while (cursor.offset < cursor.reader.size) {
    const code = await cursor.peek();
    if (code === 130) record.strings.push(await cursor.name());
    else if (code === 131) await cursor.index();
    else if (code === 128 || code === 129) await cursor.byte();
    else await cursor.numeric();
  }
};

const readScalar = async (cursor: TypeCursor, record: TypeRecord): Promise<void> => {
  await cursor.numeric();
  if (await cursor.peek() === 131) await cursor.index();
  else await cursor.numeric();
  await cursor.optionalName(record);
  if (cursor.offset === cursor.reader.size) return;
  if (await cursor.peek() === 131) await cursor.index();
  else await cursor.numeric();
  await cursor.numeric();
  await cursor.numeric();
};

const readArray = async (cursor: TypeCursor, record: TypeRecord): Promise<void> => {
  await cursor.numeric();
  await cursor.index();
  if (cursor.offset < cursor.reader.size && await cursor.peek() === 131) await cursor.index();
  await cursor.optionalName(record);
};

const readPointer = async (cursor: TypeCursor, record: TypeRecord): Promise<void> => {
  if (await cursor.peek() !== 131) await cursor.byte();
  await cursor.index();
  await cursor.optionalName(record);
};

const readStructureTags = async (cursor: TypeCursor, record: TypeRecord, fields: bigint): Promise<void> => {
  let tags = await cursor.numeric();
  if (tags < 0n) throw new Error("Negative C6 structure tag count.");
  if (fields) { await cursor.index(); record.strings = [await cursor.name()]; }
  else { await cursor.byte(); await cursor.byte(); }
  while (tags-- > 0n) {
    const count = await cursor.numeric();
    if (count < 0n) throw new Error("Negative C6 structure variant count.");
    if (fields) for (let index = 0n; index < count; index++) await cursor.numeric();
    await cursor.index(); await cursor.index();
  }
};

const readStructure = async (cursor: TypeCursor, record: TypeRecord): Promise<void> => {
  await cursor.numeric();
  const fields = await cursor.numeric();
  if (fields < 0n) throw new Error("Negative C6 structure field count.");
  if (fields) { await cursor.index(); await cursor.index(); }
  else { await cursor.byte(); await cursor.byte(); } // Two easy leaves for unions.
  await cursor.optionalName(record);
  if (cursor.offset === cursor.reader.size) return;
  if (![104, 105].includes(await cursor.byte())) throw new Error("Unknown C6 structure packing leaf.");
  if (cursor.offset < cursor.reader.size) await readStructureTags(cursor, record, fields);
};

const readArrayBounds = async (cursor: TypeCursor, record: TypeRecord): Promise<void> => {
  const tag = await cursor.byte();
  record.strings = [];
  const schema = ["s", "n", "nn", "ns", "sn", "ss", "n", "s"][tag];
  if (schema === undefined) throw new Error(`Unknown C6 FORTRAN array bounds tag ${tag}.`);
  for (const field of schema) {
    if (field === "s") record.strings.push(await cursor.name());
    else await cursor.numeric();
  }
};

const readAlias = async (cursor: TypeCursor, record: TypeRecord): Promise<void> => {
  await cursor.index(); record.name = await cursor.name();
};

const readVariableCount = async (cursor: TypeCursor): Promise<void> => {
  const code = await cursor.byte();
  if (code < 0x80) return;
  if (code < 0xc0) { await cursor.skip(1); return; }
  if ((code & 0xf0) === 0xc0 || (code & 0xf0) === 0xf0) { await cursor.skip(3); return; }
  throw new Error("Unknown C6 COBOL variable-count encoding.");
};

const readCobolItem = async (cursor: TypeCursor, record: TypeRecord, code: number): Promise<void> => {
  if (!(code & 0x80)) {
    await cursor.skip(code & 0x20 ? 1 : 2); // Numeric descriptor and optional one-byte literal.
    return;
  }
  if (code & 8) { await readVariableCount(cursor); return; }
  const size = ((code & 3) << 8) + await cursor.byte() + 1;
  if (!(code & 0x20)) {
    record.strings = [await cursor.reader.ansiBytes(cursor.offset, size)];
    cursor.offset += size;
  }
};

const readCobolFields = async (cursor: TypeCursor, record: TypeRecord): Promise<void> => {
  while (cursor.offset < cursor.reader.size) {
    const code = await cursor.byte();
    if ((code & 0xfe) === 0xc0) {
      if (code & 1) await readVariableCount(cursor);
    } else if ((code & 0xe0) === 0xe0) {
      if (code & 0x10) await readVariableCount(cursor);
      await readVariableCount(cursor);
    } else { await readCobolItem(cursor, record, code); return; }
  }
};

const readCobol = async (cursor: TypeCursor, record: TypeRecord): Promise<void> => {
  if (record.type === 166) await cursor.index();
  if (await cursor.byte() !== 0) return readCobolFields(cursor, record);
  await cursor.skip(2); // Root naming algorithm, then a counted name (without LF_STRING).
  const name = await cursor.reader.pascal(cursor.offset);
  record.name = name.name;
  cursor.offset = cursor.reader.size; // Remaining root bytes are producer-specific data.
};

const readProcedure = async (cursor: TypeCursor): Promise<void> => {
  await cursor.byte(); // Null leaf, followed by a return type or void leaf.
  if (await cursor.peek() === 131) await cursor.index();
  else await cursor.byte();
  await cursor.byte(); // Calling convention; no inline strings.
  await cursor.numeric();
  await cursor.index();
};

const readBasedPointer = async (cursor: TypeCursor): Promise<void> => {
  await cursor.index();
  const kind = await cursor.byte();
  const size = new Map([[146, 2], [147, 4], [148, 4], [151, 4], [152, 4],
    [131, 2], [128, 0], [129, 0]]).get(kind);
  if (size === undefined) throw new Error(`Unknown C6 pointer base ${kind}.`);
  await cursor.skip(size);
};

const readFortranString = async (cursor: TypeCursor): Promise<void> => {
  if (await cursor.byte() > 1) throw new Error("Unknown C6 FORTRAN string tag.");
  await cursor.numeric();
};

const READERS: Partial<Record<number, (cursor: TypeCursor, record: TypeRecord) => Promise<void>>> = {
  93: readAlias, 120: readArray, 121: readStructure, 122: readPointer,
  123: readScalar, 127: readList, 142: readArrayBounds, 166: readCobol, 167: readCobol,
  92: async cursor => { await cursor.numeric(); await cursor.skip(2); },
  96: async cursor => { await cursor.numeric(); },
  114: async cursor => { await cursor.skip(2); }, 117: readProcedure,
  118: async cursor => { await cursor.index(); }, 140: async cursor => { await cursor.index(); },
  141: readFortranString, 145: readBasedPointer,
  128: async () => {},
  144: async cursor => { await cursor.skip(2); cursor.offset = cursor.reader.size; }
};

const readTypeText = async (reader: LegacyCodeViewReader, record: TypeRecord): Promise<void> => {
  const decode = READERS[record.type];
  if (!decode) throw new Error(`C6 type leaf ${record.type} body is not decoded.`);
  const cursor = new TypeCursor(reader);
  await decode(cursor, record);
  if (cursor.offset !== reader.size) reader.warn(`C6 type ${record.type} has trailing bytes.`);
};

export const readCodeViewC6Types = async (reader: LegacyCodeViewReader): Promise<LegacyCodeViewTypes> => {
  const records: TypeRecord[] = [];
  let offset = 0;
  while (offset < reader.size) {
    try {
      const header = await reader.view(offset, 4);
      const length = header.getUint16(1, true);
      if (!length || length + 3 > reader.size - offset) throw new Error("Invalid C6 type record length.");
      const record: TypeRecord = { type: header.getUint8(3) };
      records.push(record);
      try { await readTypeText(reader.subsection(offset, length + 3), record); }
      catch (error) { reader.warn(`C6 type ${record.type}: ${String(error)}`); }
      offset += length + 3;
    } catch (error) { reader.warn(String(error)); break; }
  }
  return { kind: "types", encoding: "c6", records };
};
