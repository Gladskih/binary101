"use strict";

import type { ResourceLangEntry } from "../core.js";

export interface ResourcePreviewField {
  label: string;
  value: string;
}

export interface ResourceManifestPreview {
  manifestVersion: string | null;
  assemblyType: string | null;
  assemblyName: string | null;
  assemblyVersion: string | null;
  processorArchitecture: string | null;
  requestedExecutionLevel: string | null;
  requestedUiAccess: boolean | null;
  supportedArchitectures: string[];
}

export interface ResourceManifestValidation {
  status: "consistent" | "warnings";
  checkedCount: number;
  validated: string[];
  warnings: string[];
}

export interface ResourceManifestTreeAttribute {
  name: string;
  value: string;
}

export interface ResourceManifestTreeNode {
  name: string;
  attributes: ResourceManifestTreeAttribute[];
  text: string | null;
  children: ResourceManifestTreeNode[];
}

export interface ResourceVersionPreview {
  fileVersionString?: string;
  productVersionString?: string;
  stringValues?: Array<{ table: string; key: string; value: string }>;
  translations?: Array<{ languageId: number; codePage: number }>;
}

export interface ResourceDialogFontPreview {
  pointSize: number;
  weight: number | null;
  italic: boolean;
  charset: number | null;
  typeface: string;
}

export interface ResourceDialogControlPreview {
  id: number | null;
  kind: string;
  title: string | null;
  x: number;
  y: number;
  width: number;
  height: number;
  style: number;
  exStyle: number;
}

export interface ResourceDialogPreview {
  templateKind: "standard" | "extended";
  title: string | null;
  menu: string | null;
  className: string | null;
  x: number;
  y: number;
  width: number;
  height: number;
  style: number;
  exStyle: number;
  font: ResourceDialogFontPreview | null;
  controls: ResourceDialogControlPreview[];
}

export interface ResourceMenuItemPreview {
  text: string | null;
  id: number | null;
  type: number | null;
  state: number | null;
  flags: string[];
  children: ResourceMenuItemPreview[];
}

export interface ResourceMenuPreview {
  templateKind: "standard" | "extended";
  helpId: number | null;
  items: ResourceMenuItemPreview[];
}

export interface ResourceAcceleratorEntryPreview {
  id: number;
  key: string;
  modifiers: string[];
  flags: string[];
}

export interface ResourceAcceleratorPreview {
  entries: ResourceAcceleratorEntryPreview[];
}

export interface ResourcePreviewData {
  previewKind: string;
  textPreview?: string;
  textEncoding?: string | null;
  manifestInfo?: ResourceManifestPreview;
  manifestTree?: ResourceManifestTreeNode;
  manifestValidation?: ResourceManifestValidation;
  stringTable?: Array<{ id: number | null; text: string }>;
  messageTable?: { messages: Array<{ id: number; strings: string[] }>; truncated: boolean };
  versionInfo?: ResourceVersionPreview;
  previewFields?: ResourcePreviewField[];
  dialogPreview?: ResourceDialogPreview;
  menuPreview?: ResourceMenuPreview;
  acceleratorPreview?: ResourceAcceleratorPreview;
  previewMime?: string;
  previewDataUrl?: string;
}

export interface ResourcePreviewResult {
  preview?: ResourcePreviewData;
  issues?: string[];
}

export type ResourceLangWithPreview =
  ResourceLangEntry &
  Partial<ResourcePreviewData> & {
    previewIssues?: string[];
  };

export type ResourceDetailGroup = {
  typeName: string;
  entries: Array<{ id: number | null; name: string | null; langs: ResourceLangWithPreview[] }>;
};
