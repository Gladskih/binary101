"use strict";

import type { ResourceLangEntry } from "./resources-core.js";

export type ResourceLangWithPreview = ResourceLangEntry & {
  previewKind?: string;
  textPreview?: string;
  textEncoding?: string | null;
  stringPreview?: Array<{ id: number | null; text: string }>;
  stringTable?: Array<{ id: number | null; text: string }>;
  messageItems?: Array<{ id: number; strings: string[] }>;
  messageTable?: { messages: Array<{ id: number; strings: string[] }>; truncated: boolean };
  versionInfo?: Record<string, unknown>;
  icon?: unknown;
  previewMime?: string;
  previewDataUrl?: string;
  previewIssues?: string[];
};

export type ResourceDetailGroup = {
  typeName: string;
  entries: Array<{ id: number | null; name: string | null; langs: ResourceLangWithPreview[] }>;
};
