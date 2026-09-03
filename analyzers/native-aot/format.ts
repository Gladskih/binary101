"use strict";

// ModuleHeaders.h and ReadyToRunHeaderNode.cs define this header and its emitted layout:
// https://github.com/dotnet/runtime/blob/main/src/coreclr/nativeaot/Runtime/inc/ModuleHeaders.h
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ReadyToRunHeaderNode.cs
export const NATIVE_AOT_READY_TO_RUN_SIGNATURE = 0x0052_5452;
// MetadataBlob.cs maps EmbeddedMetadata (13) into the reserved blob range beginning at 300.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/Runtime/MetadataBlob.cs
export const NATIVE_AOT_EMBEDDED_METADATA_SECTION = 313;
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
}

export interface NativeAotReflectionType {
  namespace: string;
  name: string;
  methods: string[];
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
  205: "Eager class constructors",
  206: "Frozen-object region",
  207: "Dehydrated data",
  208: "Thread-static offsets",
  209: "Interface dispatch-cell info",
  210: "Interface dispatch cells",
  212: "Import address tables",
  213: "Module initializers",
  214: "GVM dispatch-cell info",
  215: "GVM dispatch cells",
  313: "Embedded reflection metadata"
};

export const isSupportedNativeAotSectionType = (type: number): boolean =>
  (type >= 124 && type <= 126) ||
  (type >= 200 && type <= 215) ||
  (type >= 300 && type <= 399);

export const nativeAotSectionName = (type: number): string =>
  SECTION_NAMES[type] ??
  (type >= 300 ? `NativeAOT blob ${type - 300}` : `NativeAOT section ${type}`);
