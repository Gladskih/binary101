"use strict";

import type { RvaToOffset } from "./types.js";

export interface ResourceLangEntry {
  lang: number | null;
  size: number;
  codePage: number;
  dataRVA: number;
  reserved: number;
}

export interface ResourceDetailEntry {
  id: number | null;
  name: string | null;
  langs: ResourceLangEntry[];
}

export interface ResourceTree {
  base: number;
  limitEnd: number;
  dirRva?: number;
  dirSize?: number;
  issues?: string[];
  top: Array<{ typeName: string; kind: "name" | "id"; leafCount: number }>;
  detail: Array<{ typeName: string; entries: ResourceDetailEntry[] }>;
  view: (offset: number, length: number) => Promise<DataView>;
  rvaToOff: RvaToOffset;
}
