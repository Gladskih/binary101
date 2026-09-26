import type {
  ResourceTypeLibraryPreview, ResourceTypeLibrarySegmentPreview
} from "../resources/preview/types.js";
import { readSltgBlocks, sltgHeaderFields } from "./sltg-blocks.js";
import { SltgReader } from "./sltg-reader.js";
import { readSltgType } from "./sltg-descriptors.js";
import { readSltgMembers } from "./sltg-members.js";
import { readSltgReferences, readSltgInterfaces } from "./sltg-references.js";
import { SltgHelpStrings } from "./sltg-help.js";
import { createTypeLibraryDecoder } from "./reader.js";
import type { TypeLibraryAnalysis, TypeLibraryType } from "./types.js";

// ITypeLib2_Constructor_SLTG / SLTG_ReadLibBlk in Wine typelib.c.
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.c
interface SltgTypeIdentity {
  nameOffset: number; guid: string | null; helpContext: number; help: Uint8Array
}

const readIdentities = (
  reader: SltgReader, initialOffset: number, count: number
): { identities: SltgTypeIdentity[]; next: number } => {
  const identities: SltgTypeIdentity[] = [];
  let offset = initialOffset;
  for (let index = 0; index < count; index++) {
    const first = reader.string(offset);
    const second = first ? reader.string(first.next) : null;
    if (!second || !reader.range(second.next, 6)) break;
    const start = second.next;
    const rest = start + 6 + (reader.word(start + 4) ?? 0);
    if (!reader.range(rest, 26)) break;
    identities.push({ nameOffset: reader.word(start + 2) ?? 0,
      guid: reader.guid(rest + 8), helpContext: reader.view.getUint32(rest + 2, true),
      help: reader.data.subarray(start + 6, rest) });
    offset = rest + 26;
  }
  return { identities, next: offset };
};

const readType = (
  reader: SltgReader, names: SltgReader, identity: SltgTypeIdentity, index: number,
  analysis: TypeLibraryAnalysis
): TypeLibraryType | null => {
  const layout = readTypeLayout(reader);
  if (!layout) return null;
  const { tail, members } = layout;
  members.references = readSltgReferences(reader, names, reader.view.getUint32(2, true), analysis);
  members.helpStrings = names.helpStrings;
  const flags = (reader.view.getUint8(26) >>> 3) | (reader.view.getUint8(27) << 5);
  const kind = flags & 0x40 ? 4 : reader.view.getUint8(29);
  return {
    reference: index * 100, name: names.name(identity.nameOffset), guid: identity.guid, kind, flags,
    version: reader.view.getUint32(18, true),
    size: tail.view.getUint16(32, true), alignment: tail.view.getUint16(34, true),
    vtableSize: tail.view.getUint16(40, true),
    documentation: names.helpStrings?.decode(identity.help) ?? null, helpContext: identity.helpContext,
    helpStringContext: null,
    alias: kind === 6 ? readAlias(tail, members) : null,
    dll: null, customData: [],
    interfaces: readSltgInterfaces(members, tail.view.getUint16(12, true), tail.view.getUint16(4, true)),
    ...readSltgMembers(members, names, tail)
  };
};

const readAlias = (tail: SltgReader, members: SltgReader): string =>
  tail.view.getUint16(28, true) ? readSltgType(tail, 20).type
    : readSltgType(members, tail.view.getUint16(20, true)).type;

const readTypeLayout = (reader: SltgReader): { tail: SltgReader; members: SltgReader } | null => {
  if (!reader.range(0, 34) || reader.word(0) !== 0x0501) {
    reader.warn("TYPELIB SLTG type header is truncated or has invalid magic.");
    return null;
  }
  const member = reader.view.getUint32(10, true);
  if (!reader.range(member, 9)) return null;
  const size = reader.view.getUint32(member + 5, true);
  const tailOffset = member + 9 + size;
  if (!reader.range(member + 9, size) || !reader.range(tailOffset, 54)) return null;
  const tail = reader.slice(tailOffset, tailOffset + 54);
  const members = reader.slice(member + 9, tailOffset);
  return { tail, members };
};

const readLibrary = (
  reader: SltgReader, blocks: SltgReader[], fields: ResourceTypeLibraryPreview["headerFields"]
): TypeLibraryAnalysis | undefined => {
  const info = readLibraryStrings(reader);
  if (!info) return undefined;
  const start = info.next;
  appendLibraryFields(reader, start, fields);
  const countOffset = start + 34 + 64;
  const count = reader.word(countOffset);
  if (count === null) return undefined;
  const metadata = readIdentities(reader, countOffset + 2, count);
  validateTypeCount(reader, count, blocks.length, metadata.identities.length);
  if (!reader.range(metadata.next, 4)) return undefined;
  const names = readNames(reader, metadata.next);
  if (!names) return undefined;
  const analysis: TypeLibraryAnalysis = {
    name: names.name(reader.view.getUint16(4, true)), guid: reader.guid(start + 18),
    documentation: info.documentation, helpFile: info.helpFile, helpStringDll: null,
    helpContext: reader.view.getUint32(start, true), helpStringContext: null,
    customData: [], imports: [], importedTypes: [], types: []
  };
  return { ...analysis, types: metadata.identities.flatMap((identity, index) => {
    const block = blocks[index];
    const type = block ? readType(block, names, identity, index, analysis) : null;
    return type ? [type] : [];
  }) };
};

const readLibraryStrings = (
  reader: SltgReader
): { documentation: string | null; helpFile: string | null; next: number } | null => {
  if (!reader.range(0, 8) || reader.word(0) !== 0x51cc) {
    reader.warn("TYPELIB SLTG library block is truncated or has invalid magic.");
    return null;
  }
  configureEncoding(reader);
  const reserved = reader.string(6);
  const documentation = reserved ? reader.string(reserved.next) : null;
  const helpFile = documentation ? reader.string(documentation.next) : null;
  if (!helpFile || !reader.range(helpFile.next, 34)) return null;
  return { documentation: documentation?.text ?? null, helpFile: helpFile.text, next: helpFile.next };
};

const configureEncoding = (reader: SltgReader): void => {
  let cursor = 6;
  for (let index = 0; index < 3; index++) {
    const end = reader.stringEnd(cursor);
    if (end === null) return;
    cursor = end;
  }
  const lcid = reader.word(cursor + 6);
  if (lcid !== null) reader.decoder = createTypeLibraryDecoder(lcid);
};

const appendLibraryFields = (
  reader: SltgReader, start: number, fields: ResourceTypeLibraryPreview["headerFields"]
): void => {
  fields.push(
    { label: "SYSKIND", value: String(reader.view.getUint16(start + 4, true)) },
    { label: "LCID", value: `0x${reader.view.getUint16(start + 6, true).toString(16)}` },
    { label: "Flags", value: `0x${reader.view.getUint16(start + 12, true).toString(16)}` },
    { label: "Library version", value: `${reader.view.getUint16(start + 14, true)}.${reader.view.getUint16(start + 16, true)}` }
  );
};

const validateTypeCount = (reader: SltgReader, count: number, blocks: number, identities: number): void => {
  if (count !== blocks || identities !== count) {
    reader.warn("TYPELIB SLTG type count disagrees with its blocks or metadata.");
  }
};

const readNames = (reader: SltgReader, offset: number): SltgReader | null => {
  const tableOffset = reader.view.getUint32(offset, true);
  const marker = reader.word(tableOffset);
  if (marker !== 0xffff && marker !== 0x200) {
    reader.warn("TYPELIB SLTG name table marker is invalid.");
  }
  const namesOffset = tableOffset + (marker === 0x200 ? 32 : 0) + 0x218;
  if (!reader.range(namesOffset, 0)) return null;
  const names = reader.slice(namesOffset);
  names.helpStrings = new SltgHelpStrings(reader, offset + 4);
  return names;
};

export const parseSltgLibrary = (
  data: Uint8Array, issues: string[]
): ResourceTypeLibraryPreview => {
  const segments: ResourceTypeLibrarySegmentPreview[] = readSltgBlocks(data, issues);
  const headerFields = sltgHeaderFields(data);
  const root = new SltgReader(data, issues);
  const blocks = segments.map(segment => root.slice(segment.offset, segment.offset + segment.length));
  const library = blocks.at(-1);
  const analysis = library ? readLibrary(library, blocks.slice(0, -1), headerFields) : undefined;
  return { format: "SLTG", headerFields, segments, ...(analysis ? { analysis } : {}) };
};
