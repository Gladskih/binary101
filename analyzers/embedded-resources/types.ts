import type { ResourcePreviewWithIssues } from "../pe/resources/preview/types.js";

export interface ResourceRange { offset: number; size: number }

export interface ResourcePayload extends ResourceRange {
  compression: "none" | "zlib" | "zstd";
  uncompressedSize: number;
}

export interface StoredResourceContent extends ResourceRange {
  // Only compressed data stores a separate expanded size; otherwise size is authoritative.
  uncompressedSize?: number;
}

export interface EmbeddedResourceEntry {
  name: string;
  parent: number | null;
  flags?: number;
  payload?: StoredResourceContent;
  preview?: ResourcePreviewWithIssues;
}

export interface RccNode extends EmbeddedResourceEntry {
  nameOffset: number;
  flags: number;
  nameHash?: number;
  timestamp?: bigint;
  childCount?: number;
  firstChild?: number;
  territory?: number;
  language?: number;
  dataOffset?: number;
}

export interface RccResource {
  format: "Qt RCC";
  // Compiled arrays share the v2/v3 node layout; do not invent the registration version.
  version: number | null;
  flags?: number;
  tree: ResourceRange;
  names: ResourceRange;
  data: ResourceRange;
  entries: RccNode[];
}

export interface GResourceItem extends EmbeddedResourceEntry {
  hash: number;
  keyOffset: number;
  keySize: number;
  type: "L" | "v";
  value: ResourceRange;
  children?: number[];
  flags?: number;
}

export interface GResource {
  format: "GLib GResource";
  version: number;
  options: number;
  byteSwapped: boolean;
  root: ResourceRange;
  bloomShift: number;
  bloomWords: number[];
  buckets: number[];
  entries: GResourceItem[];
}

export type EmbeddedResource = RccResource | GResource;
export interface EmbeddedResourceBundle {
  offset: number;
  evidence: string[];
  resource: EmbeddedResource;
  issues: string[];
}
export interface EmbeddedResourceAnalysis {
  bundles: EmbeddedResourceBundle[];
  issues: string[];
}
export interface ResourceDecodeResult<Type> { value: Type | null; issues: string[] }

// Symbol scope identifies one translation unit. Never associate unrelated generic RCC names.
export interface ResourceSymbol extends ResourceRange { name: string; scope: string }
export interface ResourceSection extends ResourceRange { name: string }
export interface ResourceReference { targetOffset: number; description: string }
