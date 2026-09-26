import type { SltgReader } from "./sltg-reader.js";
import { readSltgType } from "./sltg-descriptors.js";
import type { TypeLibraryFunction, TypeLibraryVariable, TypeLibraryParameter } from "./types.js";

// Packed SLTG_Function / SLTG_Variable and linked member lists (Wine typelib.h).
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.h
const readParameters = (
  reader: SltgReader, names: SltgReader, initialOffset: number, count: number, optional: number
): TypeLibraryParameter[] => {
  const result: TypeLibraryParameter[] = [];
  let offset = initialOffset;
  for (let index = 0; index < count; index++) {
    const name = reader.word(offset);
    const target = reader.word(offset + 2);
    if (name === null || target === null) break;
    const element = readSltgType(reader, name & 1 ? offset + 2 : target);
    result.push({ name: (name & ~1) === 0xfffe ? null : names.name(name & ~1),
      type: element.type, flags: element.flags | (count - index <= optional ? 16 : 0),
      defaultValue: null, customData: [] });
    offset = name & 1 ? element.next : offset + 4;
  }
  return result;
};

const readFunction = (
  reader: SltgReader, names: SltgReader, offset: number
): TypeLibraryFunction | null => {
  if (!reader.range(offset, 22)) return null;
  const view = reader.view;
  const magic = view.getUint8(offset);
  const kind = ({ 76: 1, 203: 4, 139: 3 } as Record<number, number>)[magic & ~0x20];
  if (kind === undefined || !reader.range(offset, magic & 0x20 ? 24 : 22)) {
    reader.warn("TYPELIB SLTG function magic is invalid.");
    return null;
  }
  const optional = (view.getUint8(offset + 17) & 0x7e) >>> 1;
  return {
    name: names.name(view.getUint16(offset + 4, true)), id: view.getInt32(offset + 6, true),
    type: readSltgType(reader, view.getUint8(offset + 17) & 0x80
      ? offset + 18 : view.getUint16(offset + 18, true)).type,
    kind, flags: magic & 0x20 ? view.getUint16(offset + 22, true) : 0,
    invocation: view.getUint8(offset + 1) >>> 4,
    callingConvention: view.getUint8(offset + 16) & 7,
    vtableOffset: view.getUint16(offset + 20, true) & ~1,
    optionalParameters: optional, documentation: reader.help(view.getUint16(offset + 12, true)),
    helpContext: null, helpStringContext: null, entry: null, customData: [],
    parameters: readParameters(reader, names, view.getUint16(offset + 14, true),
      view.getUint8(offset + 16) >>> 3, optional)
  };
};

const readConstant = (
  reader: SltgReader, flags: number, offset: number, type: string
): TypeLibraryVariable["value"] => {
  if (flags & 8) return { type: 22, value: offset };
  if (["BSTR", "LPSTR", "LPWSTR"].includes(type)) {
    const text = reader.string(offset);
    return text ? { type: 8, value: text.text } : null;
  }
  if (!["short", "unsigned short", "long", "unsigned long", "int", "unsigned int"].includes(type)) {
    reader.warn(`TYPELIB SLTG constant type ${type} is unsupported.`);
    return null;
  }
  return reader.range(offset, 4) ? { type: 22, value: reader.view.getInt32(offset, true) } : null;
};

const readVariable = (
  reader: SltgReader, names: SltgReader, offset: number, previous: TypeLibraryVariable | undefined
): TypeLibraryVariable | null => {
  if (!reader.range(offset, 18)) return null;
  const view = reader.view;
  const magic = view.getUint8(offset);
  if (![0x0a, 0x2a].includes(magic) || !reader.range(offset, magic === 0x2a ? 20 : 18)) {
    reader.warn("TYPELIB SLTG variable magic is invalid.");
    return null;
  }
  const flags = view.getUint8(offset + 1);
  const type = readSltgType(reader, flags & 2 ? offset + 8 : view.getUint16(offset + 8, true)).type;
  const value = view.getUint16(offset + 6, true);
  const kind = variableKind(flags);
  return { ...readVariableAttributes(reader, names, offset, previous), type, kind,
    value: kind === 2 ? readConstant(reader, flags, value, type) : null,
    instanceOffset: kind === 2 ? null : value
  };
};

const variableKind = (flags: number): number => flags & 0x40 ? 3 : flags & 0x10 ? 2 : 0;

const readVariableAttributes = (
  reader: SltgReader, names: SltgReader, offset: number, previous: TypeLibraryVariable | undefined
): Omit<TypeLibraryVariable, "type" | "kind" | "value" | "instanceOffset"> => {
  const view = reader.view;
  return {
    name: view.getUint16(offset + 4, true) === 0xfffe ? previous?.name ?? null
      : names.name(view.getUint16(offset + 4, true)), id: view.getInt32(offset + 10, true),
    flags: (view.getUint8(offset) === 0x2a ? view.getUint16(offset + 18, true) : 0)
      | (view.getUint8(offset + 1) & 0x80 ? 1 : 0),
    documentation: reader.help(view.getUint16(offset + 16, true)),
    helpContext: null, helpStringContext: null, customData: []
  };
};

const readChain = <Member>(
  reader: SltgReader, first: number, count: number,
  read: (offset: number, previous: Member | undefined) => Member | null
): Member[] => {
  const result: Member[] = [];
  const seen = new Set<number>();
  let offset = first;
  for (let index = 0; index < count; index++) {
    if (offset === 0xffff || seen.has(offset)) {
      reader.warn("TYPELIB SLTG member chain ends early or contains a cycle.");
      break;
    }
    seen.add(offset);
    const member = read(offset, result.at(-1));
    if (member === null) break;
    result.push(member);
    offset = reader.word(offset + 2) ?? 0xffff;
  }
  return result;
};

export const readSltgMembers = (
  reader: SltgReader, names: SltgReader, tail: SltgReader
): { functions: TypeLibraryFunction[]; variables: TypeLibraryVariable[] } => ({
  functions: readChain(reader, tail.word(8) ?? 0xffff, tail.word(0) ?? 0,
    offset => readFunction(reader, names, offset)),
  variables: readChain(reader, tail.word(10) ?? 0xffff, tail.word(2) ?? 0,
    (offset, previous) => readVariable(reader, names, offset, previous))
});
