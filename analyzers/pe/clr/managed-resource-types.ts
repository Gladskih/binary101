"use strict";

import type { PeClrMetadataIndex } from "./types.js";
import type { ResourcePreviewData } from "../resources/preview/types.js";

export interface PeClrManagedResourceEntry extends Partial<ResourcePreviewData> {
  row: number;
  name: string | null;
  flags: number;
  offset: number;
  implementation: PeClrMetadataIndex;
  storage: "embedded" | "external" | "unmapped" | "truncated";
  size: number | null;
  entries?: PeClrManagedResourceValue[];
  issues?: string[];
}

export interface PeClrManagedResourceValue extends Partial<ResourcePreviewData> {
  name: string;
  type: string;
  value: string | number | boolean | null;
  opaque: boolean;
  issues?: string[];
}

export interface PeClrManagedResources {
  entries: PeClrManagedResourceEntry[];
  issues: string[];
}
