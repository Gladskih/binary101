import type { ParseForUiResult } from "../analyzers/index.js";
import type { ResourceDetailGroup, ResourceLangWithPreview } from "../analyzers/pe/resources/preview/types.js";
import type { ResourceLocation } from "../analyzers/pe/resources/resource-index.js";
import type { PeResources } from "../analyzers/pe/resources/index.js";
import { createFileRangeReader } from "../analyzers/file-range-reader.js";
import { createResourcePayloadReader } from "../analyzers/pe/resources/payload-reader.js";
import { readResourceLeafBytes } from "../analyzers/pe/resources/preview/leaf-data.js";
import { addHeuristicResourcePreview } from "../analyzers/pe/resources/preview/sniff.js";
import { addBitmapPreview } from "../analyzers/pe/resources/preview/bitmap.js";
import { addIconPreview } from "../analyzers/pe/resources/preview/icon.js";
import { addCursorPreview } from "../analyzers/pe/resources/preview/cursor.js";
import { addFontPreview } from "../analyzers/pe/resources/preview/standard-types.js";
import { getResourcePreviewModel } from "../renderers/pe/resource-preview-context.js";
import { renderPreviewCell } from "../renderers/pe/resource-preview-cell.js";
import { inspectEmbeddedDocument } from "../analyzers/pe/resources/preview/embedded-document.js";

interface ResourceSelection {
  location: ResourceLocation;
  group: ResourceDetailGroup;
  entry: ResourceDetailGroup["entries"][number];
  leaf: ResourceLangWithPreview;
}

const selectedResource = (button: HTMLButtonElement, resources: PeResources): ResourceSelection | null => {
  const match = /^(\d+)-(\d+)-(\d+)$/u.exec(button.dataset["peResourcePreview"] ?? "");
  if (!match) return null;
  const [groupIndex, entryIndex, language] = match.slice(1).map(Number) as [number, number, number];
  const group = resources.detail[groupIndex];
  const entry = group?.entries[entryIndex];
  const leaf = entry?.langs[language];
  return group && entry && leaf ? { location: { group: groupIndex, entry: entryIndex, language },
    group, entry, leaf } : null;
};

const decodeResource = async (data: Uint8Array, selection: ResourceSelection) => {
  const { group, leaf } = selection;
  if (group.typeName === "FONT") return addFontPreview(data, group.typeName);
  const decoder = new Map([["BITMAP", addBitmapPreview], ["ICON", addIconPreview],
    ["CURSOR", addCursorPreview]]).get(group.typeName);
  const detected = decoder ? decoder(data, group.typeName) : await addHeuristicResourcePreview(data, leaf.codePage);
  const nested = detected?.preview?.embeddedDocument;
  return nested ? inspectEmbeddedDocument(data, nested.format) : detected;
};

const previewResource = async (data: Uint8Array, selection: ResourceSelection,
  button: HTMLButtonElement, resources: PeResources, issues: string[]): Promise<void> => {
  const decoded = await decodeResource(data, selection);
  const container = button.closest("[data-pe-resource-preview-content]");
  if (!container) return;
  container.innerHTML = renderPreviewCell({ ...selection.leaf,
    ...(decoded?.preview ?? { previewKind: "summary", previewFields: [
      { label: "Preview", value: "No supported media preview for this payload." }
    ] }), previewIssues: [...issues, ...(decoded?.issues ?? [])] }, undefined,
  { ...getResourcePreviewModel(resources), source: selection.location });
};

const performAction = async (button: HTMLButtonElement, selection: ResourceSelection,
  resources: PeResources, reader: ReturnType<typeof createResourcePayloadReader>): Promise<string[]> => {
  const payload = await readResourceLeafBytes(reader, selection.leaf);
  if (!payload.data) throw new Error(payload.issues?.join(" ") || "Resource bytes are unavailable.");
  await previewResource(payload.data, selection, button, resources, payload.issues ?? []);
  return payload.issues ?? [];
};

const actionButton = (event: Event): HTMLButtonElement | null =>
  typeof Element !== "undefined" && event.target instanceof Element ? event.target.closest<HTMLButtonElement>(
    "[data-pe-resource-preview]") : null;

export const createPeResourcePayloadClickHandler = (
  getResult: () => ParseForUiResult, getFile: () => File | null,
  setStatus: (message: string | null | undefined) => void
) => async (event: Event): Promise<void> => {
  const button = actionButton(event);
  const result = getResult();
  const file = getFile();
  if (!button || !file || result.analyzer !== "pe" || !("resources" in result.parsed)) return;
  const resources = result.parsed.resources;
  if (!resources) return;
  const selection = selectedResource(button, resources);
  if (!selection) return;
  button.disabled = true;
  try {
    const reader = createResourcePayloadReader(createFileRangeReader(file, 0, file.size), result.parsed.rvaToOff);
    setStatus((await performAction(button, selection, resources, reader)).join(" ") || null);
  } catch (error) { setStatus(`Resource action failed: ${String(error)}`); }
  finally { button.disabled = false; }
};
