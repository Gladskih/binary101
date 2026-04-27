"use strict";

export type ClrMetadataColumnKind =
  "blob" | "coded" | "guid" | "string" | "table" | "u8" | "u16" | "u32";

export interface ClrMetadataColumnSchema {
  name: string;
  kind: ClrMetadataColumnKind;
  table?: number;
  coded?: string;
}

export interface ClrMetadataTableSchema {
  id: number;
  name: string;
  columns: readonly ClrMetadataColumnSchema[];
}

export interface ClrCodedIndexSchema {
  name: string;
  tagBits: number;
  tables: readonly number[];
}

const u8 = (name: string): ClrMetadataColumnSchema => ({ name, kind: "u8" });
const u16 = (name: string): ClrMetadataColumnSchema => ({ name, kind: "u16" });
const u32 = (name: string): ClrMetadataColumnSchema => ({ name, kind: "u32" });
const str = (name: string): ClrMetadataColumnSchema => ({ name, kind: "string" });
const guid = (name: string): ClrMetadataColumnSchema => ({ name, kind: "guid" });
const blob = (name: string): ClrMetadataColumnSchema => ({ name, kind: "blob" });
const table = (name: string, tableId: number): ClrMetadataColumnSchema =>
  ({ name, kind: "table", table: tableId });
const coded = (name: string, codedName: string): ClrMetadataColumnSchema =>
  ({ name, kind: "coded", coded: codedName });

// ECMA-335 Partition II chapter 21 defines metadata table ids and columns.
// Spec: https://docs.ecma-international.org/ecma-335/Ecma-335-part-i-iv.pdf
export const TABLE_MODULE = 0x00;
export const TABLE_TYPE_REF = 0x01;
export const TABLE_TYPE_DEF = 0x02;
export const TABLE_FIELD = 0x04;
export const TABLE_METHOD_DEF = 0x06;
export const TABLE_PARAM = 0x08;
export const TABLE_MEMBER_REF = 0x0a;
export const TABLE_CUSTOM_ATTRIBUTE = 0x0c;
export const TABLE_MODULE_REF = 0x1a;
export const TABLE_IMPL_MAP = 0x1c;
export const TABLE_ASSEMBLY = 0x20;
export const TABLE_ASSEMBLY_REF = 0x23;
export const TABLE_FILE = 0x26;
export const TABLE_EXPORTED_TYPE = 0x27;
export const TABLE_MANIFEST_RESOURCE = 0x28;
export const TABLE_GENERIC_PARAM_CONSTRAINT = 0x2c;

// ECMA-335 Partition II chapter 21 table schemas, encoded in physical #~ row order.
export const CLRMETADATA_TABLES: readonly ClrMetadataTableSchema[] = [
  { id: 0x00, name: "Module", columns: [u16("Generation"), str("Name"), guid("Mvid"), guid("EncId"), guid("EncBaseId")] },
  { id: 0x01, name: "TypeRef", columns: [coded("ResolutionScope", "ResolutionScope"), str("TypeName"), str("TypeNamespace")] },
  { id: 0x02, name: "TypeDef", columns: [u32("Flags"), str("TypeName"), str("TypeNamespace"), coded("Extends", "TypeDefOrRef"), table("FieldList", 0x04), table("MethodList", 0x06)] },
  { id: 0x03, name: "FieldPtr", columns: [table("Field", 0x04)] },
  { id: 0x04, name: "Field", columns: [u16("Flags"), str("Name"), blob("Signature")] },
  { id: 0x05, name: "MethodPtr", columns: [table("Method", 0x06)] },
  { id: 0x06, name: "MethodDef", columns: [u32("RVA"), u16("ImplFlags"), u16("Flags"), str("Name"), blob("Signature"), table("ParamList", 0x08)] },
  { id: 0x07, name: "ParamPtr", columns: [table("Param", 0x08)] },
  { id: 0x08, name: "Param", columns: [u16("Flags"), u16("Sequence"), str("Name")] },
  { id: 0x09, name: "InterfaceImpl", columns: [table("Class", 0x02), coded("Interface", "TypeDefOrRef")] },
  { id: 0x0a, name: "MemberRef", columns: [coded("Class", "MemberRefParent"), str("Name"), blob("Signature")] },
  { id: 0x0b, name: "Constant", columns: [u8("Type"), u8("Padding"), coded("Parent", "HasConstant"), blob("Value")] },
  { id: 0x0c, name: "CustomAttribute", columns: [coded("Parent", "HasCustomAttribute"), coded("Type", "CustomAttributeType"), blob("Value")] },
  { id: 0x0d, name: "FieldMarshal", columns: [coded("Parent", "HasFieldMarshal"), blob("NativeType")] },
  { id: 0x0e, name: "DeclSecurity", columns: [u16("Action"), coded("Parent", "HasDeclSecurity"), blob("PermissionSet")] },
  { id: 0x0f, name: "ClassLayout", columns: [u16("PackingSize"), u32("ClassSize"), table("Parent", 0x02)] },
  { id: 0x10, name: "FieldLayout", columns: [u32("Offset"), table("Field", 0x04)] },
  { id: 0x11, name: "StandAloneSig", columns: [blob("Signature")] },
  { id: 0x12, name: "EventMap", columns: [table("Parent", 0x02), table("EventList", 0x14)] },
  { id: 0x13, name: "EventPtr", columns: [table("Event", 0x14)] },
  { id: 0x14, name: "Event", columns: [u16("EventFlags"), str("Name"), coded("EventType", "TypeDefOrRef")] },
  { id: 0x15, name: "PropertyMap", columns: [table("Parent", 0x02), table("PropertyList", 0x17)] },
  { id: 0x16, name: "PropertyPtr", columns: [table("Property", 0x17)] },
  { id: 0x17, name: "Property", columns: [u16("Flags"), str("Name"), blob("Type")] },
  { id: 0x18, name: "MethodSemantics", columns: [u16("Semantics"), table("Method", 0x06), coded("Association", "HasSemantics")] },
  { id: 0x19, name: "MethodImpl", columns: [table("Class", 0x02), coded("MethodBody", "MethodDefOrRef"), coded("MethodDeclaration", "MethodDefOrRef")] },
  { id: 0x1a, name: "ModuleRef", columns: [str("Name")] },
  { id: 0x1b, name: "TypeSpec", columns: [blob("Signature")] },
  { id: 0x1c, name: "ImplMap", columns: [u16("MappingFlags"), coded("MemberForwarded", "MemberForwarded"), str("ImportName"), table("ImportScope", 0x1a)] },
  { id: 0x1d, name: "FieldRVA", columns: [u32("RVA"), table("Field", 0x04)] },
  { id: 0x1e, name: "ENCLog", columns: [u32("Token"), u32("FuncCode")] },
  { id: 0x1f, name: "ENCMap", columns: [u32("Token")] },
  { id: 0x20, name: "Assembly", columns: [u32("HashAlgId"), u16("MajorVersion"), u16("MinorVersion"), u16("BuildNumber"), u16("RevisionNumber"), u32("Flags"), blob("PublicKey"), str("Name"), str("Culture")] },
  { id: 0x21, name: "AssemblyProcessor", columns: [u32("Processor")] },
  { id: 0x22, name: "AssemblyOS", columns: [u32("OSPlatformID"), u32("OSMajorVersion"), u32("OSMinorVersion")] },
  { id: 0x23, name: "AssemblyRef", columns: [u16("MajorVersion"), u16("MinorVersion"), u16("BuildNumber"), u16("RevisionNumber"), u32("Flags"), blob("PublicKeyOrToken"), str("Name"), str("Culture"), blob("HashValue")] },
  { id: 0x24, name: "AssemblyRefProcessor", columns: [u32("Processor"), table("AssemblyRef", 0x23)] },
  { id: 0x25, name: "AssemblyRefOS", columns: [u32("OSPlatformID"), u32("OSMajorVersion"), u32("OSMinorVersion"), table("AssemblyRef", 0x23)] },
  { id: 0x26, name: "File", columns: [u32("Flags"), str("Name"), blob("HashValue")] },
  { id: 0x27, name: "ExportedType", columns: [u32("Flags"), u32("TypeDefId"), str("TypeName"), str("TypeNamespace"), coded("Implementation", "Implementation")] },
  { id: 0x28, name: "ManifestResource", columns: [u32("Offset"), u32("Flags"), str("Name"), coded("Implementation", "Implementation")] },
  { id: 0x29, name: "NestedClass", columns: [table("NestedClass", 0x02), table("EnclosingClass", 0x02)] },
  { id: 0x2a, name: "GenericParam", columns: [u16("Number"), u16("Flags"), coded("Owner", "TypeOrMethodDef"), str("Name")] },
  { id: 0x2b, name: "MethodSpec", columns: [coded("Method", "MethodDefOrRef"), blob("Instantiation")] },
  { id: 0x2c, name: "GenericParamConstraint", columns: [table("Owner", 0x2a), coded("Constraint", "TypeDefOrRef")] }
];

// ECMA-335 Partition II table columns define these coded-index tag layouts.
export const CLR_CODED_INDEXES: readonly ClrCodedIndexSchema[] = [
  { name: "TypeDefOrRef", tagBits: 2, tables: [0x02, 0x01, 0x1b] },
  { name: "HasConstant", tagBits: 2, tables: [0x04, 0x08, 0x17] },
  { name: "HasCustomAttribute", tagBits: 5, tables: [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b] },
  { name: "HasFieldMarshal", tagBits: 1, tables: [0x04, 0x08] },
  { name: "HasDeclSecurity", tagBits: 2, tables: [0x02, 0x06, 0x20] },
  { name: "MemberRefParent", tagBits: 3, tables: [0x02, 0x01, 0x1a, 0x06, 0x1b] },
  { name: "HasSemantics", tagBits: 1, tables: [0x14, 0x17] },
  { name: "MethodDefOrRef", tagBits: 1, tables: [0x06, 0x0a] },
  { name: "MemberForwarded", tagBits: 1, tables: [0x04, 0x06] },
  { name: "Implementation", tagBits: 2, tables: [0x26, 0x23, 0x27] },
  { name: "CustomAttributeType", tagBits: 3, tables: [-1, -1, 0x06, 0x0a, -1] },
  { name: "ResolutionScope", tagBits: 2, tables: [0x00, 0x1a, 0x23, 0x01] },
  { name: "TypeOrMethodDef", tagBits: 1, tables: [0x02, 0x06] }
];

export const tableSchemaById = (tableId: number): ClrMetadataTableSchema | null =>
  CLRMETADATA_TABLES.find(tableSchema => tableSchema.id === tableId) || null;

export const tableNameById = (tableId: number): string =>
  tableSchemaById(tableId)?.name || `TABLE_${tableId.toString(16).padStart(2, "0")}`;

export const codedIndexSchemaByName = (name: string): ClrCodedIndexSchema | null =>
  CLR_CODED_INDEXES.find(codedIndex => codedIndex.name === name) || null;

export const metadataToken = (tableId: number, row: number): number =>
  ((tableId & 0xff) << 24) | (row & 0x00ffffff);
