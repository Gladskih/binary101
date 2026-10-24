import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { CodeViewCompositeShape } from "./legacy-codeview-composite-records.js";
import { readLegacyCodeViewMethods, type LegacyCodeViewMethod } from "./legacy-codeview-methods.js";

interface CodeViewProcedure {
  returnType: number;
  callingConvention: number;
  attributes: number;
  parameterCount: number;
  argumentList: number;
}
export type CodeViewTypeShape = CodeViewCompositeShape
  | (CodeViewProcedure & { kind: "procedure" })
  | (CodeViewProcedure & { kind: "memberFunction"; classType: number;
      thisType: number; thisAdjustment: number })
  | { kind: "arguments"; types: number[] }
  | { kind: "methods"; methods: LegacyCodeViewMethod[] }
  | { kind: "vtableShape"; slots: number[] }
  | { kind: "modifier"; typeIndex: number; attributes: number }
  | { kind: "pointer"; typeIndex: number; attributes: number;
      classType?: number; representation?: number }
  | { kind: "alias"; typeIndex: number }
  | { kind: "bitfield"; typeIndex: number; length: number; position: number }
  | { kind: "functionId"; scopeId: number; functionType: number }
  | { kind: "memberFunctionId"; classType: number; functionType: number }
  | { kind: "skip"; nextIndex: number };

// Packed lfProc[_16t], lfMFunc[_16t], lfArgList[_16t], lfModifier and lfPointer.
// Offsets here include the two-byte record length before each leaf.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const typeIndex = (view: DataView, offset: number, width: 2 | 4): number =>
  width === 2 ? view.getUint16(offset, true) : view.getUint32(offset, true);

const readProcedure = async (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewTypeShape> => {
  const width = leaf < 0x1000 ? 2 : 4;
  const member = leaf === 9 || leaf === 0x1009;
  const callOffset = 4 + width * (member ? 3 : 1);
  const view = await reader.view(0, callOffset + 4 + width + (member ? 4 : 0));
  const callingConvention = view.getUint8(callOffset);
  const attributes = view.getUint8(callOffset + 1);
  if (callingConvention > 0x18 || callingConvention === 6) {
    reader.warn(`CodeView function has unknown calling convention ${callingConvention}.`);
  }
  if (attributes & ~7) reader.warn(`CodeView function has unknown attribute bits ${attributes & ~7}.`);
  const procedure: CodeViewProcedure = { returnType: typeIndex(view, 4, width), callingConvention,
    attributes, parameterCount: view.getUint16(callOffset + 2, true),
    argumentList: typeIndex(view, callOffset + 4, width) };
  return member ? { kind: "memberFunction", ...procedure,
    classType: typeIndex(view, 4 + width, width), thisType: typeIndex(view, 4 + width * 2, width),
    thisAdjustment: view.getInt32(callOffset + 4 + width, true) } : { kind: "procedure", ...procedure };
};

const readArguments = async (reader: LegacyCodeViewReader, width: 2 | 4): Promise<CodeViewTypeShape> => {
  const count = typeIndex(await reader.view(4, width), 0, width);
  const view = await reader.view(4 + width, count * width);
  const types: number[] = [];
  for (let index = 0; index < count; index++) types.push(typeIndex(view, index * width, width));
  return { kind: "arguments", types };
};

const readModifier = async (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewTypeShape> => {
  const view = await reader.view(0, leaf === 1 ? 8 : 10);
  const attributes = view.getUint16(leaf === 1 ? 4 : 8, true);
  if (attributes & ~7) reader.warn(`CodeView modifier has unknown attribute bits ${attributes & ~7}.`);
  return { kind: "modifier", attributes,
    typeIndex: leaf === 1 ? view.getUint16(6, true) : view.getUint32(4, true) };
};

const readPointer = async (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewTypeShape> => {
  const width = leaf === 2 ? 2 : 4;
  const prefix = 4 + width * 2;
  const view = await reader.view(0, prefix);
  const attributes = typeIndex(view, leaf === 2 ? 4 : 8, width);
  const mode = attributes >>> 5 & 7;
  const pointer = { kind: "pointer" as const, attributes,
    typeIndex: typeIndex(view, leaf === 2 ? 6 : 4, width) };
  if (attributes & ~(leaf === 2 ? 0xfff : 0x3fffff)) reader.warn("CodeView pointer has unknown attribute bits.");
  if (mode !== 2 && mode !== 3) return pointer;
  const member = await reader.view(prefix, width + 2);
  return { ...pointer, classType: typeIndex(member, 0, width), representation: member.getUint16(width, true) };
};

const readArgumentList = (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewTypeShape> =>
  readArguments(reader, leaf === 0x201 ? 2 : 4);

const readAlias = async (reader: LegacyCodeViewReader): Promise<CodeViewTypeShape> =>
  ({ kind: "alias", typeIndex: await reader.uint32(4) });

const readFunctionId = async (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewTypeShape> => {
  const view = await reader.view(4, 8);
  const functionType = view.getUint32(4, true);
  return leaf === 0x1601 ? { kind: "functionId", scopeId: view.getUint32(0, true), functionType }
    : { kind: "memberFunctionId", classType: view.getUint32(0, true), functionType };
};

const readSkip = async (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewTypeShape> =>
  ({ kind: "skip", nextIndex: leaf === 0x200 ? await reader.uint16(4) : await reader.uint32(4) });

// lfBitfield_16t stores length/position before the type; lfBitfield stores them after.
const readBitfield = async (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewTypeShape> => {
  const view = await reader.view(0, leaf === 0x206 ? 8 : 10);
  const position = leaf === 0x206 ? 4 : 8;
  return { kind: "bitfield", typeIndex: leaf === 0x206 ? view.getUint16(6, true) : view.getUint32(4, true),
    length: view.getUint8(position), position: view.getUint8(position + 1) };
};

const readMethods = async (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewTypeShape> =>
  ({ kind: "methods", methods: await readLegacyCodeViewMethods(
    reader.subsection(4, reader.size - 4), leaf === 0x207 ? 2 : 4) });

const readVtableShape = async (reader: LegacyCodeViewReader): Promise<CodeViewTypeShape> => {
  const count = await reader.uint16(4);
  const view = await reader.view(6, Math.ceil(count / 2));
  // lfVTShape descriptors are packed high nibble first, then low nibble.
  // LLVM corrected its old reading order in 841a3c559da0fdc52ac90f394aea5ebcaf46ec9f.
  const slots = Array.from({ length: count }, (_, index) => index & 1
    ? view.getUint8(index >>> 1) & 15 : view.getUint8(index >>> 1) >>> 4);
  const unknown = new Set(slots.filter(slot => slot > 7));
  if (unknown.size) reader.warn(`CodeView has unknown vtable slot kinds: ${[...unknown].join(", ")}.`);
  return { kind: "vtableShape", slots };
};

const SHAPE_READERS = new Map<number,
  (reader: LegacyCodeViewReader, leaf: number) => Promise<CodeViewTypeShape>>([
  [8, readProcedure], [9, readProcedure], [0x1008, readProcedure], [0x1009, readProcedure],
  [0x201, readArgumentList], [0x1201, readArgumentList], [1, readModifier], [0x1001, readModifier],
  [2, readPointer], [0x1002, readPointer], [0x1010, readAlias], [0x150a, readAlias],
  [0x1601, readFunctionId], [0x1602, readFunctionId], [0x200, readSkip], [0x1200, readSkip],
  [0x206, readBitfield], [0x1205, readBitfield], [0x207, readMethods], [0x1206, readMethods],
  [10, readVtableShape]
]);

/** Read stored type relationships without resolving external PDB/type-server references. */
export const readCodeViewTypeShape = async (
  reader: LegacyCodeViewReader, leaf: number
): Promise<CodeViewTypeShape | undefined> => SHAPE_READERS.get(leaf)?.(reader, leaf);
