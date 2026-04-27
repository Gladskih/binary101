"use strict";

export interface PeClrStreamInfo {
  name: string;
  offset: number;
  size: number;
}

export interface PeClrMetadataIndex {
  table: string;
  tableId: number;
  row: number;
  raw: number;
  tag?: number;
  token?: number;
  valid: boolean;
}

export interface PeClrTableRowCount {
  tableId: number;
  name: string;
  rows: number;
  known: boolean;
  sorted: boolean;
}

export interface PeClrModuleInfo {
  row: number;
  name: string | null;
  mvid: string | null;
}

export interface PeClrAssemblyInfo {
  row: number;
  name: string | null;
  culture: string | null;
  version: string;
  hashAlgorithm: number;
  flags: number;
  publicKeySize: number | null;
}

export interface PeClrAssemblyRefInfo {
  row: number;
  name: string | null;
  culture: string | null;
  version: string;
  flags: number;
  publicKeyOrTokenSize: number | null;
  hashValueSize: number | null;
}

export interface PeClrTypeReferenceInfo {
  row: number;
  name: string | null;
  namespace: string | null;
  resolutionScope: PeClrMetadataIndex;
  fullName: string | null;
}

export interface PeClrTypeDefinitionInfo {
  row: number;
  name: string | null;
  namespace: string | null;
  fullName: string | null;
  flags: number;
  extends: PeClrMetadataIndex;
  fieldStart: number;
  methodStart: number;
  methodEnd: number | null;
}

export interface PeClrMethodSignature {
  callingConvention: number;
  genericParameterCount?: number;
  parameterCount: number;
  returnType: string | null;
  parameterTypes: Array<string | null>;
  issues?: string[];
}

export interface PeClrMethodDefinitionInfo {
  row: number;
  name: string | null;
  ownerType: string | null;
  rva: number;
  implFlags: number;
  flags: number;
  signatureBlobIndex: number;
  signature?: PeClrMethodSignature;
}

export interface PeClrMemberReferenceInfo {
  row: number;
  name: string | null;
  parent: PeClrMetadataIndex;
  parentName: string | null;
  signatureBlobIndex: number;
  signature?: PeClrMethodSignature;
}

export interface PeClrModuleReferenceInfo {
  row: number;
  name: string | null;
}

export interface PeClrImplementationMapInfo {
  row: number;
  mappingFlags: number;
  member: PeClrMetadataIndex;
  memberName: string | null;
  importName: string | null;
  importScopeName: string | null;
}

export interface PeClrFileInfo {
  row: number;
  name: string | null;
  flags: number;
  hashValueSize: number | null;
}

export interface PeClrExportedTypeInfo {
  row: number;
  name: string | null;
  namespace: string | null;
  fullName: string | null;
  flags: number;
  typeDefId: number;
  implementation: PeClrMetadataIndex;
}

export interface PeClrManifestResourceInfo {
  row: number;
  name: string | null;
  offset: number;
  flags: number;
  implementation: PeClrMetadataIndex;
}

export interface PeClrCustomAttributeArgument {
  type: string | null;
  value: string | number | boolean | null;
}

export interface PeClrCustomAttributeNamedArgument extends PeClrCustomAttributeArgument {
  kind: "field" | "property";
  name: string | null;
}

export interface PeClrCustomAttributeInfo {
  row: number;
  parent: PeClrMetadataIndex;
  parentName: string | null;
  constructor: PeClrMetadataIndex | null;
  constructorName: string | null;
  attributeType: string | null;
  valueBlobIndex: number;
  fixedArguments: PeClrCustomAttributeArgument[];
  namedArguments: PeClrCustomAttributeNamedArgument[];
  issues?: string[];
}

export interface PeClrMetadataTables {
  streamName: "#~" | "#-";
  majorVersion: number;
  minorVersion: number;
  heapSizes: number;
  largestRidLog2: number;
  extraData?: number;
  validMask: string;
  sortedMask: string;
  heapIndexSizes: {
    string: number;
    guid: number;
    blob: number;
  };
  rowCounts: PeClrTableRowCount[];
  modules: PeClrModuleInfo[];
  assembly: PeClrAssemblyInfo | null;
  assemblyRefs: PeClrAssemblyRefInfo[];
  typeRefs: PeClrTypeReferenceInfo[];
  typeDefs: PeClrTypeDefinitionInfo[];
  methodDefs: PeClrMethodDefinitionInfo[];
  memberRefs: PeClrMemberReferenceInfo[];
  moduleRefs: PeClrModuleReferenceInfo[];
  implMaps: PeClrImplementationMapInfo[];
  files: PeClrFileInfo[];
  exportedTypes: PeClrExportedTypeInfo[];
  manifestResources: PeClrManifestResourceInfo[];
  customAttributes: PeClrCustomAttributeInfo[];
}

export interface PeClrMeta {
  version?: string;
  verMajor?: number;
  verMinor?: number;
  reserved?: number;
  flags?: number;
  streamCount?: number;
  signature?: number;
  streams: PeClrStreamInfo[];
  tables?: PeClrMetadataTables;
}

export interface PeClrVTableFixup {
  RVA: number;
  Count: number;
  Type: number;
}

export interface PeClrHeader {
  cb: number;
  MajorRuntimeVersion: number;
  MinorRuntimeVersion: number;
  MetaDataRVA: number;
  MetaDataSize: number;
  Flags: number;
  EntryPointToken: number;
  ResourcesRVA: number;
  ResourcesSize: number;
  StrongNameSignatureRVA: number;
  StrongNameSignatureSize: number;
  CodeManagerTableRVA: number;
  CodeManagerTableSize: number;
  VTableFixupsRVA: number;
  VTableFixupsSize: number;
  ExportAddressTableJumpsRVA: number;
  ExportAddressTableJumpsSize: number;
  ManagedNativeHeaderRVA: number;
  ManagedNativeHeaderSize: number;
  meta?: PeClrMeta;
  vtableFixups?: PeClrVTableFixup[];
  issues?: string[];
}
