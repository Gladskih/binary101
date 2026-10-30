import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { Td32SymbolRecord } from "./td32-symbol-types.js";

type SymbolFields = Omit<Td32SymbolRecord, "type">;
interface SymbolLayout { size: number; decode: (fields: DataView) => SymbolFields; }

// All positions include reclen/rectyp. Unlike NBxx, TD32 uses DWORD shared-name indices.
// Common procedure prefix: JCL TSymbolProcInfo and map2dbg LoadSymbol agree.
// Their procedure-type/flag fields at +34..+39 disagree: leave those uninterpreted.
// https://github.com/project-jedi/jcl/blob/10b92737050d9aaa0af17fe099a737d390b6c80e/jcl/source/windows/JclTD32.pas#L455
// https://github.com/andremussche/map2dbg/blob/70cd89ff693cd622215309b0acb4326e530e7884/tds2pdb/tds2pdb/Program.cs#L2470
const procedure = (view: DataView): SymbolFields => ({ nameIndex: view.getUint32(40, true), metadata: {
  scopeOffsets: { parent: view.getUint32(4, true), end: view.getUint32(8, true), next: view.getUint32(12, true) },
  codeLength: view.getUint32(16, true), debugRange: { start: view.getUint32(20, true), end: view.getUint32(24, true) },
  location: { offset: view.getUint32(28, true), segment: view.getUint16(32, true) } } });
const data = (view: DataView): SymbolFields => ({ nameIndex: view.getUint32(16, true), metadata: {
  location: { offset: view.getUint32(4, true), segment: view.getUint16(8, true) },
  flags: view.getUint16(10, true), typeIndex: view.getUint32(12, true) } });
const reference = (view: DataView): SymbolFields => ({ nameIndex: view.getUint32(12, true), metadata: {
  typeIndex: view.getUint32(8, true),
  location: { offset: view.getUint32(20, true), segment: view.getUint16(24, true) } } });
const block = (view: DataView): SymbolFields => ({ nameIndex: view.getUint32(22, true), metadata: {
  scopeOffsets: { parent: view.getUint32(4, true), end: view.getUint32(8, true) },
  codeLength: view.getUint32(12, true),
  location: { offset: view.getUint32(16, true), segment: view.getUint16(20, true) } } });

const LAYOUTS = new Map<number, SymbolLayout>([
  [2, { size: 14, decode: view => ({ nameIndex: view.getUint32(10, true), metadata: {
    typeIndex: view.getUint32(4, true), register: view.getUint16(8, true) } }) }],
  [3, { size: 12, decode: view => ({ nameIndex: view.getUint32(8, true),
    metadata: { typeIndex: view.getUint32(4, true) } }) }],
  [4, { size: 14, decode: view => ({ nameIndex: view.getUint32(10, true), metadata: {
    typeIndex: view.getUint32(4, true), flags: view.getUint16(8, true) } }) }],
  [0x200, { size: 16, decode: view => ({ nameIndex: view.getUint32(12, true), metadata: {
    frameOffset: view.getInt32(4, true), typeIndex: view.getUint32(8, true) } }) }],
  ...[0x201, 0x202, 0x203].map(type => [type, { size: 20, decode: data }] as const),
  ...[0x204, 0x205].map(type => [type, { size: 44, decode: procedure }] as const),
  ...[0x20, 0x21].map(type => [type, { size: 26, decode: reference }] as const),
  [0x207, { size: 26, decode: block }],
  [0x210, { size: 10, decode: view => ({ metadata: {
    location: { offset: view.getUint32(4, true), segment: view.getUint16(8, true) } } }) }],
  [0x211, { size: 16, decode: view => ({ metadata: { rangeStart: view.getUint32(6, true),
    codeLength: view.getUint32(10, true), register: view.getUint16(14, true) } }) }],
  [0x212, { size: 10, decode: view => ({ metadata: {
    rangeStart: view.getUint32(4, true), codeLength: view.getUint16(8, true) } }) }],
  [0x213, { size: 6, decode: view => ({ metadata: { flags: view.getUint16(4, true) } }) }],
  [0x209, { size: 11, decode: view => ({ metadata: { flags: view.getUint8(10),
    location: { offset: view.getUint32(4, true), segment: view.getUint16(8, true) } } }) }],
  [0x25, { size: 14, decode: view => ({ nameIndex: view.getUint32(4, true),
    metadata: { usingCount: view.getUint16(12, true) } }) }],
  [0x27, { size: 22, decode: view => ({ nameIndex: view.getUint32(10, true), metadata: {
    typeIndex: view.getUint32(4, true), flags: view.getUint16(8, true), value: String(view.getInt32(18, true)) } }) }]
]);

const readImports = async (reader: LegacyCodeViewReader, type: number): Promise<SymbolFields> => {
  const start = type === 0x26 ? 6 : 4;
  const count = type === 0x26 ? await reader.uint16(4) : Math.floor((reader.size - 4) / 4);
  const fields = await reader.view(start, count * 4);
  if (start + count * 4 !== reader.size) reader.warn("TD32 import list has unexpected trailing bytes.");
  return { metadata: { nameIndices: Array.from({ length: count }, (_, index) => fields.getUint32(index * 4, true)) } };
};

const readThunk = async (reader: LegacyCodeViewReader): Promise<SymbolFields> => {
  const view = await reader.view(0, 29);
  const metadata = { scopeOffsets: { parent: view.getUint32(4, true), end: view.getUint32(8, true),
    next: view.getUint32(12, true) }, location: { offset: view.getUint32(16, true), segment: view.getUint16(20, true) },
  codeLength: view.getUint16(22, true), ordinal: view.getUint8(24) };
  const result: SymbolFields = { nameIndex: view.getUint32(25, true), metadata };
  if (metadata.ordinal === 1) {
    try {
      const variant = await reader.view(29, 8);
      result.metadata!.adjustment = variant.getInt32(0, true);
      result.metadata!.targetNameIndex = variant.getUint32(4, true);
    } catch (error) { reader.warn(`TD32 thunk variant: ${String(error)}`); }
  } else if (metadata.ordinal > 1) reader.warn("TD32 thunk variant has no confirmed semantic decoder.");
  return result;
};

const DYNAMIC_READERS = new Map<number, (reader: LegacyCodeViewReader, type: number) => Promise<SymbolFields>>([
  [0x24, readImports], [0x26, readImports], [0x206, readThunk]
]);

const validate = (reader: LegacyCodeViewReader, result: SymbolFields): void => {
  const metadata = result.metadata!;
  const debug = metadata.debugRange;
  if (debug && (debug.start > debug.end || debug.end > metadata.codeLength!)) reader.warn("TD32 procedure debug span exceeds its code length.");
  const start = metadata.location?.offset ?? metadata.rangeStart;
  if (start !== undefined && metadata.codeLength !== undefined && start + metadata.codeLength > 0x100000000) {
    reader.warn("TD32 symbol range exceeds 32-bit stored offsets.");
  }
};

export const readTd32SymbolMetadata = async (reader: LegacyCodeViewReader,
  type: number): Promise<SymbolFields | undefined> => {
  const layout = LAYOUTS.get(type);
  const dynamic = DYNAMIC_READERS.get(type);
  if (!layout && !dynamic) return undefined;
  try {
    const result = layout ? layout.decode(await reader.view(0, layout.size)) : await dynamic!(reader, type);
    if (type === 0x209) reader.warn("TD32 label name layouts differ between known producers; its name reference is unresolved.");
    validate(reader, result);
    return result;
  } catch (error) { reader.warn(`TD32 symbol metadata ${type}: ${String(error)}`); return undefined; }
};
