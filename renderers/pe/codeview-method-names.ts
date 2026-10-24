import type { LegacyCodeViewTypeRecord } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import type { LegacyCodeViewField } from "../../analyzers/pe/debug/legacy-codeview-fields.js";
import type { LegacyCodeViewMethod } from "../../analyzers/pe/debug/legacy-codeview-methods.js";

export interface CodeViewFunctionName {
  name: string;
  attributes?: number | undefined;
  vtableOffset?: number | undefined;
}
type MethodReference = Pick<LegacyCodeViewMethod, "typeIndex"> & CodeViewFunctionName;

const ONE_METHODS = new Set([0x40c, 0x140b, 0x1511]);
const OVERLOADED_METHODS = new Set([0x408, 0x1407, 0x150f]);

const methodReferences = (member: LegacyCodeViewField,
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>): MethodReference[] => {
  if (member.typeIndex === undefined) return [];
  const name = member.name || "(unnamed method)";
  if (ONE_METHODS.has(member.type)) return [{ name, typeIndex: member.typeIndex,
    attributes: member.attributes, vtableOffset: member.vtableOffset }];
  if (!OVERLOADED_METHODS.has(member.type)) return [];
  const list = indexed.get(member.typeIndex)?.shape;
  return list?.kind === "methods" ? list.methods.map(method => ({ ...method, name })) : [];
};

const sameName = (left: CodeViewFunctionName, right: CodeViewFunctionName): boolean =>
  left.name === right.name && left.attributes === right.attributes && left.vtableOffset === right.vtableOffset;

const addMethod = (names: Map<number, CodeViewFunctionName[]>, method: MethodReference,
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>, format: (index: number) => string): void => {
  const shape = indexed.get(method.typeIndex)?.shape;
  const name = shape?.kind === "memberFunction" ? `${format(shape.classType)}::${method.name}` : method.name;
  const candidate: CodeViewFunctionName = { name, attributes: method.attributes, vtableOffset: method.vtableOffset };
  const group = names.get(method.typeIndex) ?? [];
  if (!group.some(known => sameName(known, candidate))) group.push(candidate);
  names.set(method.typeIndex, group);
};

/** Bind only known local field-list identities; unresolved targets still retain their names. */
export const codeViewMethodNames = (records: readonly LegacyCodeViewTypeRecord[],
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>,
  format: (index: number) => string): Map<number, CodeViewFunctionName[]> => {
  const names = new Map<number, CodeViewFunctionName[]>();
  for (const record of records) {
    if (record.index === undefined || indexed.get(record.index) !== record) continue;
    for (const member of record.members ?? []) {
      for (const method of methodReferences(member, indexed)) addMethod(names, method, indexed, format);
    }
  }
  return names;
};
