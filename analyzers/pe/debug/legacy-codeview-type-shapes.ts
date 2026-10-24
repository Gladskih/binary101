import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { CodeViewCompositeShape } from "./legacy-codeview-composite-records.js";
import { readLegacyCodeViewMethods, type LegacyCodeViewMethod } from "./legacy-codeview-methods.js";
import { readCodeViewIndexList, readCodeViewTypeLinks, type CodeViewTypeLinks } from "./legacy-codeview-type-links.js";
import { readCodeViewPrecompiledType, type CodeViewPrecompiledType } from "./legacy-codeview-precompiled.js";
import { readCodeViewDimensions, type CodeViewDimensions } from "./legacy-codeview-dimensions.js";
import { readLegacyCodeViewNumeric, type LegacyCodeViewNumeric } from "./legacy-codeview-numeric.js";

type CodeViewHlslNumeric = Pick<LegacyCodeViewNumeric, "leaf" | "value">;

interface CodeViewProcedure {
  returnType: number;
  callingConvention: number;
  attributes: number;
  parameterCount: number;
  argumentList: number;
}
export type CodeViewTypeShape = CodeViewCompositeShape | CodeViewTypeLinks
  | CodeViewPrecompiledType | CodeViewDimensions
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
  | { kind: "basicArray"; typeIndex: number }
  | { kind: "label"; mode: number }
  | { kind: "extendedModifier"; typeIndex: number; modifiers: number[] }
  | { kind: "hlsl"; subtypeIndex: number; builtinKind: number; reservedBits: number;
      propertyCount: number; properties: CodeViewHlslNumeric[]; byteSize?: CodeViewHlslNumeric }
  | { kind: "bitfield"; typeIndex: number; length: number; position: number }
  | { kind: "functionId"; scopeId: number; functionType: number }
  | { kind: "memberFunctionId"; classType: number; functionType: number }
  | { kind: "skip"; nextIndex: number };

// Packed lfProc[_16t], lfMFunc[_16t], lfArgList[_16t], lfModifier and lfPointer,
// plus lfBArray[_16t], lfLabel and lfModifierEx.
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

const readArguments = async (reader: LegacyCodeViewReader, width: 2 | 4): Promise<CodeViewTypeShape> =>
  ({ kind: "arguments", types: await readCodeViewIndexList(reader, width, width) });

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

const readBasicArray = async (reader: LegacyCodeViewReader, leaf: number): Promise<CodeViewTypeShape> =>
  ({ kind: "basicArray", typeIndex: leaf === 0x000d ? await reader.uint16(4) : await reader.uint32(4) });

const readLabel = async (reader: LegacyCodeViewReader): Promise<CodeViewTypeShape> => {
  const mode = await reader.uint16(4);
  // CV_LABEL uses near return (0) and far return (4), independent of PE bitness.
  if (mode !== 0 && mode !== 4) reader.warn(`CodeView label has unknown mode ${mode}.`);
  return { kind: "label", mode };
};

// CV_modifier_e is an enum (not a bitmask); values come from cvconst.h.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvconst.h
const MODIFIER_ENUMS = new Set([0, 1, 2, 3, ...Array.from({ length: 15 }, (_, index) => 0x200 + index)]);

const readExtendedModifier = async (reader: LegacyCodeViewReader): Promise<CodeViewTypeShape> => {
  // lfModifierEx has a 32-bit type, 16-bit count, then count 16-bit enum values.
  const header = await reader.view(4, 6);
  const typeIndex = header.getUint32(0, true);
  const count = header.getUint16(4, true);
  const available = Math.floor((reader.size - 10) / 2);
  const decoded = Math.min(count, available);
  const view = await reader.view(10, decoded * 2);
  const modifiers = Array.from({ length: decoded }, (_, index) => view.getUint16(index * 2, true));
  if (decoded < count) reader.warn("CodeView extended modifier list is truncated.");
  const invalid = modifiers.filter(value => !MODIFIER_ENUMS.has(value));
  if (invalid.length) reader.warn(`CodeView extended modifier has unknown modifier enum values: ${[...new Set(invalid)].join(", ")}.`);
  if (modifiers.includes(0)) reader.warn("CodeView extended modifier has invalid modifier enum value 0.");
  return { kind: "extendedModifier", typeIndex, modifiers };
};

const HLSL_BUILTIN_KINDS = new Set([0, ...Array.from({ length: 36 }, (_, index) => 0x200 + index)]);

const hlslNumeric = ({ leaf, value }: LegacyCodeViewNumeric): CodeViewHlslNumeric => ({
  ...(leaf === undefined ? {} : { leaf }), ...(value === undefined ? {} : { value })
});

const readHlsl = async (reader: LegacyCodeViewReader): Promise<CodeViewTypeShape> => {
  const header = await reader.view(4, 8);
  const subtypeIndex = header.getUint32(0, true);
  const builtinKind = header.getUint16(4, true);
  const packedCount = header.getUint16(6, true);
  const count = packedCount & 0x0f;
  const reservedBits = packedCount >>> 4;
  if (reservedBits) reader.warn(`CodeView HLSL type has nonzero reserved bits 0x${reservedBits.toString(16)}.`);
  if (!HLSL_BUILTIN_KINDS.has(builtinKind)) reader.warn(`CodeView HLSL type has unknown built-in kind 0x${builtinKind.toString(16)}.`);
  const properties: CodeViewHlslNumeric[] = [];
  let offset = 12;
  for (let index = 0; index < count; index++) {
    try {
      const numeric = await readLegacyCodeViewNumeric(reader, offset);
      properties.push(hlslNumeric(numeric));
      offset = numeric.end;
    } catch (error) {
      reader.warn(`CodeView HLSL numeric property ${index + 1}: ${String(error)}`);
      return { kind: "hlsl", subtypeIndex, builtinKind, reservedBits, propertyCount: count, properties };
    }
  }
  try {
    const numeric = await readLegacyCodeViewNumeric(reader, offset);
    return { kind: "hlsl", subtypeIndex, builtinKind, reservedBits, propertyCount: count, properties,
      byteSize: hlslNumeric(numeric) };
  } catch (error) {
    reader.warn(`CodeView HLSL byte size: ${String(error)}`);
    return { kind: "hlsl", subtypeIndex, builtinKind, reservedBits, propertyCount: count, properties };
  }
};

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
  (reader: LegacyCodeViewReader, leaf: number) => Promise<CodeViewTypeShape | undefined>>([
  [8, readProcedure], [9, readProcedure], [0x1008, readProcedure], [0x1009, readProcedure],
  [0x201, readArgumentList], [0x1201, readArgumentList], [1, readModifier], [0x1001, readModifier],
  [2, readPointer], [0x1002, readPointer], [0x1010, readAlias], [0x150a, readAlias],
  [0x1601, readFunctionId], [0x1602, readFunctionId], [0x200, readSkip], [0x1200, readSkip],
  [0x000d, readBasicArray], [0x100b, readBasicArray], [0x000e, readLabel], [0x1518, readExtendedModifier],
  [0x1517, readHlsl],
  [0x206, readBitfield], [0x1205, readBitfield], [0x207, readMethods], [0x1206, readMethods],
  [10, readVtableShape], [0x13, readCodeViewPrecompiledType], [0x100e, readCodeViewPrecompiledType],
  [0x1509, readCodeViewPrecompiledType], [0x14, readCodeViewPrecompiledType],
  [0x11, readCodeViewDimensions], [0x100c, readCodeViewDimensions], [0x1508, readCodeViewDimensions],
  [0x208, readCodeViewDimensions], [0x209, readCodeViewDimensions],
  [0x1207, readCodeViewDimensions], [0x1208, readCodeViewDimensions],
  [0x20a, readCodeViewDimensions], [0x20b, readCodeViewDimensions],
  [0x1209, readCodeViewDimensions], [0x120a, readCodeViewDimensions]
]);

/** Read stored type relationships without resolving external PDB/type-server references. */
export const readCodeViewTypeShape = async (
  reader: LegacyCodeViewReader, leaf: number
): Promise<CodeViewTypeShape | undefined> =>
  SHAPE_READERS.get(leaf)?.(reader, leaf) ?? readCodeViewTypeLinks(reader, leaf);
