import type { Td32Types } from "../../analyzers/pe/debug/td32-type-records.js";
import type { Td32TypeField } from "../../analyzers/pe/debug/td32-type-member-types.js";
import type { Td32TypeMethod } from "../../analyzers/pe/debug/td32-type-member-types.js";
import type { Td32Table } from "./td32-tables.js";
import type { Td32TypeBody } from "../../analyzers/pe/debug/td32-type-body-types.js";

type TypeRecord = Td32Types["records"][number];
// Borland map2dbg PrimitiveType, AccessType, MPropType and field leaf values.
// https://github.com/andremussche/map2dbg/blob/70cd89ff693cd622215309b0acb4326e530e7884/tds2pdb/tds2pdb/Program.cs
const PRIMITIVES: Readonly<Partial<Record<number, string>>> = { 3: "Void", 0x74: "Int32", 0x76: "Int64" };
const FIELD_KINDS: Readonly<Partial<Record<number, string>>> = {
  0x400: "Base class", 0x401: "Virtual base class", 0x402: "Indirect virtual base class",
  0x403: "Enum value", 0x406: "Field", 0x407: "Static field", 0x408: "Method group",
  0x409: "Nested type", 0x40a: "Vtable pointer"
};
const METHOD_KINDS = ["Nonvirtual", "Virtual", "Static", "Friend", "Introducing virtual",
  "Pure virtual", "Pure introducing virtual"];
const sharedName = (names: readonly string[], index: number | undefined): string | undefined =>
  index ? names[index - 1] : undefined;
const accessText = (attributes: number | undefined): string => attributes === undefined ? ""
  : ["Unspecified", "Private", "Protected", "Public"][attributes & 3]!;
const typeName = (records: ReadonlyMap<number, TypeRecord>, names: readonly string[],
  reference: number | undefined): string => PRIMITIVES[reference ?? -1]
    ?? sharedName(names, records.get((reference ?? 0) - 0x1000)?.nameIndex) ?? "Type name unavailable";
const fieldList = (records: ReadonlyMap<number, TypeRecord>, reference: number): Td32TypeField[] | undefined => {
  const record = records.get(reference - 0x1000);
  return record?.type === 0x204 ? record.body?.fields : undefined;
};
const methodList = (records: ReadonlyMap<number, TypeRecord>, reference: number | undefined)
  : Td32TypeMethod[] | undefined => {
  const record = records.get((reference ?? 0) - 0x1000);
  return record?.type === 0x207 ? record.body?.methods : undefined;
};

const resolveFields = (records: ReadonlyMap<number, TypeRecord>, initial: number,
  owner: string, claimed: Map<string, string>) => {
  const fields: Td32TypeField[] = [];
  const issues: string[] = [];
  const shared: string[] = [];
  const visited = new Set<number>();
  const pending = [initial];
  while (pending.length) {
    const reference = pending.pop()!;
    if (visited.has(reference)) { issues.push("Cyclic or repeated field-list continuation"); continue; }
    visited.add(reference);
    const canonical = claimed.get(`fields:${reference}`);
    if (canonical) { shared.push(canonical); continue; }
    const members = fieldList(records, reference);
    if (!members) {
      issues.push("Field-list target is missing, undecoded or has a different kind"); continue;
    }
    claimed.set(`fields:${reference}`, owner);
    for (const field of members) {
      if (field.type === 0x405) pending.push(field.targetType!);
      else fields.push(field);
    }
  }
  return { fields, issues, shared };
};
const parameterCount = (body: Td32TypeBody | undefined): string =>
  body?.parameterCount === undefined ? "Not decoded" : String(body.parameterCount);
const vtableOffset = (method: Td32TypeMethod): string =>
  method.vtableOffset === undefined ? "" : String(method.vtableOffset);

const appendSignature = (method: Td32TypeMethod, owner: string, name: string,
  records: ReadonlyMap<number, TypeRecord>, names: readonly string[], tables: Td32Table[],
  origin: readonly string[]): void => {
  const candidate = records.get(method.methodType - 0x1000);
  const signature = candidate?.type === 9 ? candidate : undefined;
  if (!signature?.body) {
    tables[2]!.rows.push([owner, "Method signature target is missing, undecoded or has a different kind", ...origin]);
  }
  tables[1]!.rows.push([owner, name,
    parameterCount(signature?.body),
    typeName(records, names, signature?.body?.returnType), accessText(method.attributes),
    METHOD_KINDS[method.attributes >> 2 & 7] ?? "Unknown method kind",
    vtableOffset(method), ...origin]);
};

const appendMethods = (field: Td32TypeField, owner: string, records: ReadonlyMap<number, TypeRecord>,
  names: readonly string[], tables: Td32Table[], origin: readonly string[], claimed: Map<string, string>): void => {
  if (field.type !== 0x408) return;
  const methods = methodList(records, field.targetType);
  if (!methods) {
    tables[2]!.rows.push([owner, "Method-list target is missing, undecoded or has a different kind", ...origin]);
    return;
  }
  if (methods.length !== field.count) {
    tables[2]!.rows.push([owner, "Method-group count differs from decoded method-list length", ...origin]);
  }
  const name = sharedName(names, field.nameIndex) ?? "Unresolved member name";
  const canonical = claimed.get(`methods:${field.targetType}`);
  if (canonical) { tables[3]!.rows.push([`${owner}.${name}`, canonical, ...origin]); return; }
  claimed.set(`methods:${field.targetType}`, `${owner}.${name}`);
  for (const method of methods.slice(0, field.count ?? 0)) {
    appendSignature(method, owner, name, records, names, tables, origin);
  }
};
const memberName = (field: Td32TypeField, names: readonly string[]): string =>
  sharedName(names, field.nameIndex)
    ?? (field.nameIndex ? "Unresolved member name" : FIELD_KINDS[field.type] ?? "Unnamed member");
const memberColumns = (field: Td32TypeField, records: ReadonlyMap<number, TypeRecord>,
  names: readonly string[]): string[] => [memberName(field, names),
  FIELD_KINDS[field.type] ?? "Unknown member kind", typeName(records, names, field.targetType),
  field.offset?.value ?? field.value?.value ?? "", accessText(field.attributes),
  field.count === undefined ? "" : String(field.count)];

const appendOwner = (owner: string, fieldList: number, records: ReadonlyMap<number, TypeRecord>,
  names: readonly string[], tables: Td32Table[], origin: readonly string[], claimed: Map<string, string>): void => {
  const resolved = resolveFields(records, fieldList, owner, claimed);
  for (const field of resolved.fields) {
    tables[0]!.rows.push([owner, ...memberColumns(field, records, names), ...origin]);
    appendMethods(field, owner, records, names, tables, origin, claimed);
  }
  for (const issue of resolved.issues) tables[2]!.rows.push([owner, issue, ...origin]);
  for (const shared of resolved.shared) tables[3]!.rows.push([owner, shared, ...origin]);
};

const groupOwners = (types: Td32Types, names: readonly string[]): ReadonlyMap<number, string[]> => {
  const owners = new Map<number, string[]>();
  for (const record of types.records) {
    const name = sharedName(names, record.nameIndex);
    if (!name || !record.body?.fieldList) continue;
    const group = owners.get(record.body.fieldList);
    if (group) group.push(name);
    else owners.set(record.body.fieldList, [name]);
  }
  return owners;
};

export const buildTd32MemberTables = (types: Td32Types, names: readonly string[],
  generation: number, module: number): Td32Table[] => {
  const records = new Map(types.records.map(record => [record.index, record]));
  const tables: Td32Table[] = [
    { key: "typemembers", title: "TD32 named type members", columns: ["Owner", "Name", "Kind", "Type",
      "Offset/value", "Access", "Overloads", "Directory", "Module"], rows: [] },
    { key: "typemethods", title: "TD32 named methods", columns: ["Owner", "Method", "Parameters", "Return type",
      "Access", "Method kind", "Vtable offset", "Directory", "Module"], rows: [] },
    { key: "typememberissues", title: "TD32 member relationship issues",
      columns: ["Owner", "Issue", "Directory", "Module"], rows: [] },
    { key: "typeownership", title: "TD32 shared member-list ownership",
      columns: ["Name", "Member group", "Directory", "Module"], rows: [] }
  ];
  const origin = [String(generation), String(module)];
  const claimed = new Map<string, string>();
  for (const [fieldList, owners] of groupOwners(types, names)) {
    const label = owners.length === 1 ? owners[0]! : `${owners[0]} (shared by ${owners.length} named types)`;
    appendOwner(label, fieldList, records, names, tables, origin, claimed);
    if (owners.length > 1) for (const owner of new Set(owners)) tables[3]!.rows.push([owner, label, ...origin]);
  }
  return tables.filter(table => table.rows.length);
};
