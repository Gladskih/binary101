import type { NativeAotTemplateLayout } from "./template-layout.js";
import type { NativeAotTypeMapEntry } from "./runtime-type-map.js";
import type { NativeAotMethodIdentity } from "./layout-method-identity.js";

export interface NativeAotStructMarshallingEntry {
  typeIndex: number;
  header: number;
  nativeSize?: number;
  marshalRva: number | null;
  unmarshalRva: number | null;
  cleanupRva: number | null;
  fields: { name: string; offset: number }[];
}

export interface NativeAotDelegateMarshallingEntry {
  typeIndex: number;
  openStaticRva: number | null;
  closedRva: number | null;
  forwardCreationRva: number | null;
}

export type NativeAotExactMethodEntry = NativeAotMethodIdentity & {
  declaringTypeIndex: number;
  genericArgumentIndices: number[];
  entrypointRva: number | null;
};

export type NativeAotTemplateMethodEntry = NativeAotExactMethodEntry & {
  signatureOffset: number;
  layoutOffset: number;
  flags: number;
  layout?: NativeAotTemplateLayout;
};

export interface NativeAotTemplateTypeEntry {
  typeIndex: number;
  layoutOffset: number;
  layout: NativeAotTemplateLayout;
}

export type NativeAotFunctionMap =
  | { type: 301; entries: NativeAotTypeMapEntry[]; warnings: string[] }
  | { type: 310; entries: { typeIndex: number; staticBaseIndex: number;
    entrypointRva: number | null }[]; warnings: string[] }
  | { type: 316; entries: NativeAotStructMarshallingEntry[]; warnings: string[] }
  | { type: 317; entries: NativeAotDelegateMarshallingEntry[]; warnings: string[] }
  | { type: 321; entries: NativeAotTemplateTypeEntry[]; warnings: string[] }
  | { type: 322; entries: NativeAotTemplateMethodEntry[]; warnings: string[] }
  | { type: 336; entries: NativeAotExactMethodEntry[]; warnings: string[] };

export interface NativeAotFunctionMaps {
  maps: NativeAotFunctionMap[];
  warnings: string[];
}
