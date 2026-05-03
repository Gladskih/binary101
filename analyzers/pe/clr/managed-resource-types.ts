"use strict";

import type { PeClrMetadataIndex } from "./types.js";

export interface PeClrManagedResourceEntry {
  row: number;
  name: string | null;
  flags: number;
  offset: number;
  implementation: PeClrMetadataIndex;
  storage: "embedded" | "external" | "unmapped" | "truncated";
  size: number | null;
  entries?: PeClrManagedResourceValue[];
  previewKind?: string;
  previewMime?: string;
  previewDataUrl?: string;
  textPreview?: string;
  textEncoding?: string | null;
  previewFields?: Array<{ label: string; value: string }>;
  issues?: string[];
}

export interface PeClrManagedResourceValue {
  name: string;
  type: string;
  value: string | number | boolean | null;
  opaque: boolean;
  previewKind?: string;
  previewMime?: string;
  previewDataUrl?: string;
  textPreview?: string;
  textEncoding?: string | null;
  previewFields?: Array<{ label: string; value: string }>;
  issues?: string[];
}

export interface PeClrManagedResources {
  entries: PeClrManagedResourceEntry[];
  issues: string[];
}
