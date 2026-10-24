import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewField } from "../../analyzers/pe/debug/legacy-codeview-fields.js";
import type { LegacyCodeViewTypeRecord, LegacyCodeViewTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { legacyCodeViewFieldName } from "./legacy-codeview-kinds.js";
import { createCodeViewTypeFormatter, indexCodeViewTypes } from "./codeview-type-names.js";
import { createCodeViewFieldListResolver } from "./codeview-field-lists.js";
import { codeViewMemberAttributes } from "./codeview-member-attributes.js";

// CV_fldattr_t in Microsoft cvinfo.h; virtual-base placement follows LLVM's
// VirtualBaseClassRecord::VBPtrOffset and VTableIndex (not a second byte offset).
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/include/llvm/DebugInfo/CodeView/TypeRecord.h
const memberProperties = (member: LegacyCodeViewField, format: (index: number) => string): string => [
  ...codeViewMemberAttributes(member.attributes ?? 0),
  member.methodCount === undefined ? "" : `${member.methodCount} declared overloads`,
  member.virtualBasePointer === undefined ? "" : `virtual base pointer: ${format(member.virtualBasePointer)}`,
  member.continuation === undefined ? "" : `continues field list #${member.continuation}`
].filter(Boolean).join("; ") || "none";

const virtualBasePlacement = (member: LegacyCodeViewField): string =>
  `vbptr offset: ${member.offset ?? "unavailable"} bytes; ` +
  `vbtable index: ${member.virtualBaseTableIndex ?? "unavailable"}`;

const memberPlacement = (member: LegacyCodeViewField): string => {
  if (member.type === 0x403 || member.type === 0x1502) return member.value ?? "unavailable";
  if (member.virtualBasePointer !== undefined) return virtualBasePlacement(member);
  if (member.vtableOffset !== undefined) return `vtable offset: ${member.vtableOffset} bytes`;
  if (member.offset !== undefined) return `offset: ${member.offset} bytes`;
  return [0x406, 0x1405, 0x150d, 0x400, 0x1400, 0x151a].includes(member.type) ? "unavailable" : "—";
};

const fieldOwners = (records: readonly LegacyCodeViewTypeRecord[], format: (index: number) => string,
  resolve: ReturnType<typeof createCodeViewFieldListResolver>): ReadonlyMap<LegacyCodeViewTypeRecord, Set<string>> => {
  const owners = new Map<LegacyCodeViewTypeRecord, Set<string>>();
  for (const record of records) {
    if (record.index === undefined || record.shape?.kind !== "aggregate" || !record.shape.fieldList) continue;
    const resolved = resolve(record.shape.fieldList);
    const label = format(record.index) + (resolved.issues.length ? ` (${resolved.issues.join("; ")})` : "");
    for (const list of resolved.lists) {
      const names = owners.get(list) ?? new Set<string>();
      names.add(label);
      owners.set(list, names);
    }
  }
  return owners;
};

const ownerText = (record: LegacyCodeViewTypeRecord, owners: ReadonlyMap<LegacyCodeViewTypeRecord, Set<string>>,
  resolve: ReturnType<typeof createCodeViewFieldListResolver>): string => {
  const names = owners.get(record);
  if (names) return [...names].join("; ");
  if (record.index === undefined) return "unresolved namespace";
  return ["unassociated", ...resolve(record.index).issues].join("; ");
};

const memberRows = (data: LegacyCodeViewTypes): string[][] => {
  const indexed = indexCodeViewTypes(data.records);
  const format = createCodeViewTypeFormatter(indexed);
  const resolve = createCodeViewFieldListResolver(indexed);
  const owners = fieldOwners(data.records, format, resolve);
  const externalFormat = createCodeViewTypeFormatter(new Map());
  return data.records.flatMap(record => {
    if (!record.members) return [];
    const memberFormat = record.index === undefined ? externalFormat : format;
    const owner = ownerText(record, owners, resolve);
    return record.members.map(member => [legacyCodeViewFieldName(member.type), member.name || "(unnamed)",
      member.typeIndex === undefined ? "—" : memberFormat(member.typeIndex),
      memberPlacement(member), memberProperties(member, memberFormat), owner]);
  });
};

export const buildCodeViewMemberTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const table: LegacyCodeViewTable = { key: "members", title: "Member and enumerator names",
    columns: ["Directory", "Module", "Member kind", "Name", "Type", "Value / placement", "Properties", "Owner type"], rows: [] };
  info.directories.forEach((directory, index) => {
    for (const section of directory.subsections) {
      if (section.data?.kind !== "types") continue;
      for (const row of memberRows(section.data)) table.rows.push([String(index + 1), String(section.module), ...row]);
    }
  });
  return table.rows.length ? [table] : [];
};
