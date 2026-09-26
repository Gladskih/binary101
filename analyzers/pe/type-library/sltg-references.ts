import type { SltgReader } from "./sltg-reader.js";
import type { TypeLibraryAnalysis, TypeLibraryInterface } from "./types.js";

// SLTG_DoRefs: strings *\R<library-name-offset>*#<type-index> (hex), or ffff for local.
// Imported library name: *\G{GUID}#major.minor#lcid#filename#.
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.c
const resolveReference = (
  names: SltgReader, libraryOffset: number, index: number, analysis: TypeLibraryAnalysis
): number => {
  if (libraryOffset === 0xffff) return index * 100;
  if (!analysis.imports.some(entry => entry.offset === libraryOffset)) {
    const library = readImportedLibrary(names, libraryOffset);
    if (library) analysis.imports.push(library);
  }
  const found = analysis.importedTypes.find(entry =>
    entry.libraryOffset === libraryOffset && entry.identifier === index);
  if (found) return found.offset | 1;
  const offset = analysis.importedTypes.length * 12;
  analysis.importedTypes.push({ offset, flags: null, libraryOffset, identifier: index });
  return offset | 1;
};

const readImportedLibrary = (
  names: SltgReader, offset: number
): TypeLibraryAnalysis["imports"][number] | null => {
  const match = names.name(offset)?.match(
    /^\*\\G\{([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}#(\d+)\.(\d+)#([0-9a-f]+)#(.+)#$/i
  );
  if (!match) {
    names.warn("TYPELIB SLTG imported library string is invalid.");
    return null;
  }
  const major = Number(match[2]);
  const minor = Number(match[3]);
  const lcid = Number.parseInt(match[4]!, 16);
  if (major > 0xffff || minor > 0xffff || !Number.isSafeInteger(lcid) || lcid > 0xffffffff) {
    names.warn("TYPELIB SLTG imported library version or locale is invalid.");
    return null;
  }
  return { offset, guid: match[1]!, version: major + minor * 65536, lcid, name: match[5]! };
};

export const readSltgReferences = (
  reader: SltgReader, names: SltgReader, offset: number, analysis: TypeLibraryAnalysis
): Map<number, number> => {
  const result = new Map<number, number>();
  if (offset === 0xffffffff) return result;
  if (!reader.range(offset, 72) || reader.view.getUint8(offset) !== 0xdf) {
    reader.warn("TYPELIB SLTG reference header is invalid.");
    return result;
  }
  const bytes = reader.view.getUint32(offset + 68, true);
  if (bytes % 8) {
    reader.warn("TYPELIB SLTG reference count is not aligned to its record size.");
    return result;
  }
  if (!reader.range(offset + 72, bytes + 7)) return result;
  return readReferenceChain(reader, names, offset + 72 + bytes + 7, bytes / 8, analysis);
};

const readReferenceChain = (
  reader: SltgReader, names: SltgReader, first: number, count: number, analysis: TypeLibraryAnalysis
): Map<number, number> => {
  const result = new Map<number, number>();
  let cursor = first;
  for (let index = 0; index < count; index++) {
    const entry = readReferenceEntry(reader, names, cursor, analysis);
    if (!entry) break;
    if (entry.reference !== null) result.set(index, entry.reference);
    cursor = entry.next;
  }
  return result;
};

const readReferenceEntry = (
  reader: SltgReader, names: SltgReader, offset: number, analysis: TypeLibraryAnalysis
): { reference: number | null; next: number } | null => {
  const entry = reader.string(offset);
  if (!entry) return null;
  const match = entry.text?.match(/^\*\\R([0-9a-f]+)\*#([0-9a-f]+)$/i);
  if (!match) {
    reader.warn("TYPELIB SLTG reference string is invalid.");
    return { reference: null, next: entry.next };
  }
  const libraryOffset = Number.parseInt(match[1]!, 16);
  const index = Number.parseInt(match[2]!, 16);
  if (![libraryOffset, index].every(value => Number.isSafeInteger(value) && value <= 0xffffffff)) {
    reader.warn("TYPELIB SLTG reference library offset or type index is invalid.");
    return { reference: null, next: entry.next };
  }
  return { reference: resolveReference(names, libraryOffset, index, analysis), next: entry.next };
};

const isInterfaceRecord = (reader: SltgReader, offset: number): boolean =>
  reader.range(offset, 22) && reader.word(offset) === 0x004a;

export const readSltgInterfaces = (
  reader: SltgReader, first: number, count: number
): TypeLibraryInterface[] => {
  const result: TypeLibraryInterface[] = [];
  const seen = new Set<number>();
  let offset = first;
  for (let index = 0; index < count; index++) {
    if (seen.has(offset) || !isInterfaceRecord(reader, offset)) {
      reader.warn("TYPELIB SLTG interface chain is cyclic or invalid.");
      break;
    }
    seen.add(offset);
    const reference = reader.references.get(reader.word(offset + 10) ?? 0);
    if (reference === undefined) reader.warn("TYPELIB SLTG interface reference is invalid.");
    result.push({ reference: reference ?? -1, flags: reader.view.getUint8(offset + 6), customData: [] });
    offset = reader.word(offset + 2) ?? 0xffff;
  }
  return result;
};
