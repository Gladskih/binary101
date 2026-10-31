import type { ParseForUiResult } from "../analyzers/index.js";
import { createFileRangeReader } from "../analyzers/file-range-reader.js";
import { readEmbeddedResourceContent } from "../analyzers/embedded-resources/content.js";
import type { EmbeddedResourceEntry, ResourcePayload } from "../analyzers/embedded-resources/types.js";
import { resolveResourcePayload } from "../analyzers/embedded-resources/payload.js";

const findEntry = (result: ParseForUiResult, button: HTMLButtonElement):
  { entry: EmbeddedResourceEntry; payload: ResourcePayload | null } | null => {
  if (result.analyzer !== "pe" && result.analyzer !== "elf") return null;
  const resource = result.parsed.embeddedResources?.bundles[Number(button.dataset["embeddedResourceBundle"])]?.resource;
  const entry = resource?.entries[Number(button.dataset["embeddedResourceEntry"])];
  return resource && entry ? { entry, payload: resolveResourcePayload(resource.format, entry) } : null;
};

const contentBlob = async (file: File, payload: ResourcePayload): Promise<Blob> => {
  if (payload.compression === "none") return file.slice(payload.offset, payload.offset + payload.size);
  const content = await readEmbeddedResourceContent(createFileRangeReader(file, 0, file.size),
    payload, 256 * 1024 * 1024);
  if (!content.value) throw new Error(content.issues.join("; "));
  return new Blob([new Uint8Array(content.value)]);
};

const downloadBlob = (blob: Blob, name: string): void => {
  const url = URL.createObjectURL(blob);
  try {
    const link = document.createElement("a");
    link.href = url;
    link.download = name.split(/[\\/]/u).at(-1) || "resource.bin";
    link.click();
  } finally {
    URL.revokeObjectURL(url);
  }
};

export const createEmbeddedResourceClickHandler = (deps: {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
}) => async (event: Event): Promise<void> => {
  const button = event.target instanceof Element
    ? event.target.closest<HTMLButtonElement>("button[data-embedded-resource-bundle]") : null;
  if (!button) return;
  const selected = findEntry(deps.getParseResult(), button);
  const file = deps.getFile();
  if (!selected?.payload || !file) return;
  button.disabled = true;
  try {
    downloadBlob(await contentBlob(file, selected.payload), selected.entry.name);
  } catch (error) {
    deps.setStatusMessage(`Resource extraction failed: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    button.disabled = false;
  }
};
