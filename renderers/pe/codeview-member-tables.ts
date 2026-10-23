import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewField } from "../../analyzers/pe/debug/legacy-codeview-fields.js";
import type { LegacyCodeViewTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { legacyCodeViewFieldName } from "./legacy-codeview-kinds.js";
import { createCodeViewTypeFormatter, indexCodeViewTypes } from "./codeview-type-names.js";

// CV_fldattr_t in Microsoft cvinfo.h; virtual-base placement follows LLVM's
// VirtualBaseClassRecord::VBPtrOffset and VTableIndex (not a second byte offset).
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/include/llvm/DebugInfo/CodeView/TypeRecord.h
const attributeFlags = (attributes: number): string[] => [
  attributes & 0x20 ? "compiler-generated declaration" : "", attributes & 0x40 ? "not inheritable" : "",
  attributes & 0x80 ? "not constructible" : "", attributes & 0x100 ? "compiler-generated definition" : "",
  attributes & 0x200 ? "sealed" : "",
  attributes & ~0x3ff ? `unknown attribute bits 0x${(attributes & ~0x3ff).toString(16)}` : ""
].filter(Boolean);

const memberAttributes = (attributes: number): string[] => {
  const method = attributes >>> 2 & 7;
  return [["", "private", "protected", "public"][attributes & 3]!,
    ["", "virtual", "static", "friend", "introducing virtual", "pure virtual", "pure introducing virtual"][method]
      ?? `unknown method property ${method}`, ...attributeFlags(attributes)].filter(Boolean);
};

const memberProperties = (member: LegacyCodeViewField, format: (index: number) => string): string => [
  ...memberAttributes(member.attributes ?? 0),
  member.methodCount === undefined ? "" : `${member.methodCount} overloads`,
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

const memberRows = (data: LegacyCodeViewTypes): string[][] => {
  const format = createCodeViewTypeFormatter(indexCodeViewTypes(data.records));
  return data.records.flatMap(record => (record.members ?? []).map(member => [
    legacyCodeViewFieldName(member.type), member.name || "(unnamed)",
    member.typeIndex === undefined ? "—" : format(member.typeIndex),
    memberPlacement(member), memberProperties(member, format)
  ]));
};

export const buildCodeViewMemberTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const table: LegacyCodeViewTable = { key: "members", title: "Member and enumerator names",
    columns: ["Directory", "Module", "Member kind", "Name", "Type", "Value / placement", "Properties"], rows: [] };
  info.directories.forEach((directory, index) => {
    for (const section of directory.subsections) {
      if (section.data?.kind !== "types") continue;
      for (const row of memberRows(section.data)) table.rows.push([String(index + 1), String(section.module), ...row]);
    }
  });
  return table.rows.length ? [table] : [];
};
