import type { LegacyCodeViewTypeRecord } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import type { CodeViewTypeShape } from "../../analyzers/pe/debug/legacy-codeview-type-shapes.js";
import { legacyCodeViewTypeName, legacyCodeViewVtableSlotName } from "./legacy-codeview-kinds.js";

// TYPE_ENUM_e and CV_prmode_e: primitive identity includes width and pointer model.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
const PRIMITIVES = new Map<number, string>([
  [0, "no type"], [1, "absolute symbol"], [2, "segment"], [3, "void"], [4, "currency64"],
  [5, "near BASIC string"], [6, "far BASIC string"], [7, "not translated"], [8, "HRESULT"],
  [0x10, "signed char"], [0x11, "short16"], [0x12, "long32"], [0x13, "long64"], [0x14, "long128"],
  [0x20, "unsigned char"], [0x21, "unsigned short16"], [0x22, "unsigned long32"],
  [0x23, "unsigned long64"], [0x24, "unsigned long128"],
  [0x30, "bool8"], [0x31, "bool16"], [0x32, "bool32"], [0x33, "bool64"],
  [0x40, "float32"], [0x41, "float64"], [0x42, "float80"], [0x43, "float128"], [0x44, "float48"],
  [0x45, "partial float32"], [0x46, "float16"], [0x50, "complex32"], [0x51, "complex64"],
  [0x52, "complex80"], [0x53, "complex128"], [0x68, "int8"], [0x69, "uint8"],
  [0x70, "char"], [0x71, "wchar_t"], [0x72, "int16"], [0x73, "uint16"],
  [0x74, "int32"], [0x75, "uint32"], [0x76, "int64"], [0x77, "uint64"],
  [0x78, "int128"], [0x79, "uint128"], [0x7a, "char16"], [0x7b, "char32"],
  [0x60, "bit"], [0x61, "Pascal CHAR"], [0x62, "bool32 (true = all bits set)"]
]);

const primitiveName = (index: number): string => {
  const mode = index >>> 8;
  const name = PRIMITIVES.get(index & 255);
  if (!name || mode > 7) return `unknown primitive #${index}`;
  return mode === 0 ? name : `${["", "near16", "far16", "huge16", "near32", "far32", "near64", "near128"][mode]} pointer to ${name}`;
};

export const indexCodeViewTypes = (
  records: readonly LegacyCodeViewTypeRecord[]
): ReadonlyMap<number, LegacyCodeViewTypeRecord | null> => {
  const indexed = new Map<number, LegacyCodeViewTypeRecord | null>();
  for (const record of records) {
    if (record.index !== undefined) indexed.set(record.index, indexed.has(record.index) ? null : record);
  }
  return indexed;
};

const modifierText = (attributes: number): string => [
  attributes & 1 ? "const" : "", attributes & 2 ? "volatile" : "", attributes & 4 ? "unaligned" : "",
  attributes & ~7 ? `unknown modifier bits 0x${(attributes & ~7).toString(16)}` : ""
].filter(Boolean).join(" ");

const pointerQualifiers = (attributes: number): string[] => [
  attributes & 0x200 ? "volatile" : "", attributes & 0x400 ? "const" : "",
  attributes & 0x800 ? "unaligned" : "", attributes & 0x1000 ? "restrict" : ""
].filter(Boolean);

const pointerText = (shape: Extract<CodeViewTypeShape, { kind: "pointer" }>,
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>): string => {
  const mode = shape.attributes >>> 5 & 7;
  const model = ["near16", "far16", "huge16", "segment-based", "value-based", "segment-value-based",
    "address-based", "segment-address-based", "type-based", "self-based", "near32", "far32", "near64"][shape.attributes & 31]
    ?? `unknown model ${shape.attributes & 31}`;
  const owner = shape.classType === undefined ? "" : indexed.get(shape.classType)?.name ?? `type #${shape.classType}`;
  const label = ["pointer", "lvalue reference", `data-member pointer of ${owner}`,
    `member-function pointer of ${owner}`, "rvalue reference"][mode] ?? `unknown pointer mode ${mode}`;
  return [...pointerQualifiers(shape.attributes), `${label} (${model}) to`].join(" ");
};

interface TypeStep { text: string; next?: number }

const arrayStep = (shape: Extract<CodeViewTypeShape, { kind: "array" | "vector" | "matrix" }>): TypeStep => {
  const size = shape.size ?? "unavailable";
  if (shape.kind === "vector") return {
    text: `vector (elements: ${shape.count}, byte size: ${size}) of`, next: shape.elementType
  };
  if (shape.kind === "matrix") return {
    text: `matrix (${shape.rows} × ${shape.columns}, byte size: ${size}) of`, next: shape.elementType
  };
  return { text: `array (byte size: ${size}) of`, next: shape.elementType };
};

const referencedStep = (shape: CodeViewTypeShape,
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>): TypeStep | undefined => {
  switch (shape.kind) {
    case "modifier": return { text: modifierText(shape.attributes), next: shape.typeIndex };
    case "pointer": return { text: pointerText(shape, indexed), next: shape.typeIndex };
    case "alias": return { text: "", next: shape.typeIndex };
    case "bitfield": return {
      text: `bitfield (bit width: ${shape.length}, bit offset: ${shape.position}) of`, next: shape.typeIndex
    };
    case "array": case "vector": case "matrix": return arrayStep(shape);
    default: return undefined;
  }
};

const vtableSummary = (slots: readonly number[]): string => {
  const counts = new Map<number, number>();
  for (const slot of slots) counts.set(slot, (counts.get(slot) ?? 0) + 1);
  // CV_VTS_desc_e from the same cvinfo.h as primitive and pointer identities.
  const statistics = [...counts].sort(([left], [right]) => left - right)
    .map(([slot, count]) => `${legacyCodeViewVtableSlotName(slot)}: ${count}`).join("; ");
  return `vtable (slots: ${slots.length}${statistics ? `; ${statistics}` : ""})`;
};

const shapeSummary = (shape: CodeViewTypeShape): TypeStep | undefined => {
  if (shape.kind === "methods") return { text: `method list (variants: ${shape.methods.length})` };
  return shape.kind === "vtableShape" ? { text: vtableSummary(shape.slots) } : undefined;
};

const typeStep = (record: LegacyCodeViewTypeRecord,
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>): TypeStep => {
  if (record.name) return { text: record.name };
  return (record.shape ? referencedStep(record.shape, indexed) ?? shapeSummary(record.shape) : undefined) ?? {
    text: record.name === undefined ? `${legacyCodeViewTypeName(record.type)} #${record.index}` : "(unnamed type)"
  };
};

const formatType = (initial: number, indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>): string => {
  if ((initial >>> 0) !== initial) return `invalid type index ${initial}`;
  const visited = new Set<number>();
  const parts: string[] = [];
  let index = initial;
  while (index >= 0x1000) {
    if (visited.has(index)) return [...parts, `recursive type #${index}`].join(" ");
    visited.add(index);
    const record = indexed.get(index);
    if (!record) return [...parts, `${record === null ? "ambiguous" : "unresolved"} type #${index}`].join(" ");
    const step = typeStep(record, indexed);
    if (step.text) parts.push(step.text);
    if (step.next === undefined) return parts.join(" ");
    index = step.next;
  }
  return [...parts.filter(Boolean), primitiveName(index)].join(" ");
};

/** Resolve only this subsection's namespace; cycles and missing types stay visible. */
export const createCodeViewTypeFormatter = (indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>) => {
  const names = new Map<number, string>();
  return (index: number): string => {
    if (!names.has(index)) names.set(index, formatType(index, indexed));
    return names.get(index)!;
  };
};
