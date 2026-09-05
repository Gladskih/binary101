"use strict";

// ModuleHeaders.h and ReadyToRunHeaderNode.cs define this header and its emitted layout:
// https://github.com/dotnet/runtime/blob/main/src/coreclr/nativeaot/Runtime/inc/ModuleHeaders.h
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ReadyToRunHeaderNode.cs
export const NATIVE_AOT_READY_TO_RUN_SIGNATURE = 0x0052_5452;
// MetadataBlob.cs defines ReflectionMapBlob IDs in the reserved range beginning at 300.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/Runtime/MetadataBlob.cs
export const NATIVE_AOT_EMBEDDED_METADATA_SECTION = 313;
// ModuleHeaders.cs: ReadyToRunSectionType.EagerCctor and ModuleInitializerList.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
export const NATIVE_AOT_EAGER_CCTOR_SECTION = 205;
export const NATIVE_AOT_MODULE_INITIALIZER_LIST_SECTION = 213;
// NativeMetadataReader.cs MetadataHeader.Signature identifies NativeFormat reflection metadata.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeMetadataReader.cs
export const NATIVE_AOT_METADATA_SIGNATURE = 0xdead_dffd;
export const NATIVE_AOT_HEADER_SIZE = 16;

export type NativeAotMetadataLayout =
  | "nativeaot-readytorun-pointer-range-v1"
  | "nativeaot-readytorun-size-pointer-v1";

// Addresses are image-relative values normalized by the container adapter.
export interface NativeAotMetadataSection {
  type: number;
  rva: number;
  size: number | null;
}

export interface NativeAotMetadata {
  status: "confirmed";
  layout: NativeAotMetadataLayout;
  modulePointerRva: number;
  headerRva: number;
  majorVersion: number;
  minorVersion: number;
  sections: NativeAotMetadataSection[];
  reflection?: NativeAotReflectionMetadata;
  initializers?: NativeAotInitializerTable[];
}

export interface NativeAotInitializerTable {
  sectionType: number;
  targetRvas: number[];
  warnings: string[];
}

export interface NativeAotReflectionType {
  namespace: string;
  name: string;
  methods: string[];
  fields: string[];
}

export interface NativeAotReflectionScope {
  name: string;
  moduleName: string;
  version: { major: number; minor: number; build: number; revision: number };
  types: NativeAotReflectionType[];
}

export interface NativeAotReflectionMetadata {
  scopes: NativeAotReflectionScope[];
  warnings?: string[];
}

const SECTION_NAMES: Readonly<Record<number, string>> = {
  124: "External type maps",
  125: "Proxy type maps",
  126: "Type-map assembly targets",
  200: "String table",
  201: "GC static region",
  202: "Thread-static region",
  204: "Type-manager indirection",
  [NATIVE_AOT_EAGER_CCTOR_SECTION]: "Eager class constructors",
  206: "Frozen-object region",
  207: "Dehydrated data",
  208: "Thread-static offsets",
  209: "Interface dispatch-cell info",
  210: "Interface dispatch cells",
  212: "Import address tables",
  [NATIVE_AOT_MODULE_INITIALIZER_LIST_SECTION]: "Module initializers",
  214: "GVM dispatch-cell info",
  215: "GVM dispatch cells",
  // ReflectionMapBlob IDs below are offset by 300 in the ReadyToRun section table:
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/Runtime/MetadataBlob.cs
  301: "Type map",
  302: "Array map",
  303: "Pointer-type map",
  304: "Function-pointer-type map",
  306: "Invoke map",
  307: "Virtual-invoke map",
  308: "Common fixups table",
  309: "Field-access map",
  310: "Class-constructor context map",
  311: "By-reference-type map",
  [NATIVE_AOT_EMBEDDED_METADATA_SECTION]: "Embedded reflection metadata",
  316: "Struct marshalling-stub map",
  317: "Delegate marshalling-stub map",
  318: "Generic virtual-method table",
  319: "Interface generic virtual-method table",
  321: "Type-template map",
  322: "Generic-methods template map",
  324: "Resource index",
  325: "Resource data",
  326: "Stack-trace embedded metadata",
  327: "Stack-trace method-RVA-to-token map",
  328: "Stack-trace line numbers",
  329: "Stack-trace documents",
  330: "Native-layout info",
  331: "Native references",
  332: "Generics hash table",
  333: "Native statics",
  334: "Statics-info hash table",
  335: "Generic-methods hash table",
  336: "Exact-method-instantiations hash table"
};

export const isSupportedNativeAotSectionType = (type: number): boolean =>
  (type >= 124 && type <= 126) ||
  (type >= 200 && type <= 215) ||
  (type >= 300 && type <= 399);

export const nativeAotSectionName = (type: number): string =>
  SECTION_NAMES[type] ??
  (type >= 300 ? `NativeAOT blob ${type - 300}` : `NativeAOT section ${type}`);
