"use strict";

import { addBitmapPreview } from "./resources-preview-bitmap.js";
import { addCursorPreview, addGroupCursorPreview } from "./resources-preview-cursor.js";
import { addDialogPreview } from "./resources-preview-dialog.js";
import { addAcceleratorPreview } from "./resources-preview-accelerator.js";
import { buildResourceLeafIndex, chooseResourceLeafRecord } from "./resource-preview-leaf-index.js";
import {
  addGroupIconPreview,
  addIconPreview,
  type LoadedResourceLeaf,
  type LoadResourceLeafData
} from "./resources-preview-icon.js";
import { addMenuPreview } from "./resources-preview-menu.js";
import { addHeuristicResourcePreview } from "./resources-preview-sniff.js";
import {
  addHtmlPreview,
  addManifestPreview,
  addStringTablePreview
} from "./resources-preview-text.js";
import { addVersionPreview } from "./resources-preview-version.js";
import { decodeMessageTablePreview } from "./resources-preview-message-table.js";
import type {
  ResourceDetailGroup,
  ResourceLangWithPreview,
  ResourcePreviewResult
} from "./resources-preview-types.js";
import type { ResourceTree } from "./resources-core.js";
import type { ResourceLeafIndex } from "./resource-preview-leaf-index.js";

type ResourceEntryPreviewDecode = ResourcePreviewResult[];
type ResourceGroupPreviewDecode = ResourceEntryPreviewDecode[];

const combineIssues = (...lists: Array<string[] | undefined>): string[] | undefined => {
  const issues = lists.flatMap(list => list || []);
  return issues.length ? issues : undefined;
};

const addMessageTableResourcePreview = (
  data: Uint8Array,
  typeName: string,
  codePage: number | undefined
): ResourcePreviewResult | null => {
  if (typeName !== "MESSAGETABLE") return null;
  const messageTable = decodeMessageTablePreview(data, codePage || 0);
  if (!messageTable) return null;
  const issues = combineIssues(
    messageTable.truncated ? ["Message table preview is truncated or malformed."] : undefined,
    messageTable.issues
  );
  return {
    preview: {
      previewKind: "messageTable",
      messageTable: {
        messages: messageTable.messages,
        truncated: messageTable.truncated
      }
    },
    ...(issues ? { issues } : {})
  };
};

const runSyncPreviewDecoder = (fn: () => ResourcePreviewResult | null): ResourcePreviewResult | null => {
  try {
    return fn();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { issues: [`Preview failed: ${message}`] };
  }
};

const runAsyncPreviewDecoder = async (
  fn: () => Promise<ResourcePreviewResult | null>
): Promise<ResourcePreviewResult | null> => {
  try {
    return await fn();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { issues: [`Preview failed: ${message}`] };
  }
};

const createGroupLeafLoader = (
  file: File,
  tree: ResourceTree,
  index: ResourceLeafIndex,
  groupTypeName: "GROUP_ICON" | "GROUP_CURSOR",
  leafTypeName: "ICON" | "CURSOR"
): LoadResourceLeafData => async (
  id: number,
  lang: number | null | undefined
): Promise<LoadedResourceLeaf> => {
  const record = chooseResourceLeafRecord(index, id, lang);
  if (!record) return { data: null };
  const offset = tree.rvaToOff(record.dataRva);
  if (offset == null || offset < 0) {
    return {
      data: null,
      issues: [
        `${groupTypeName} references ${leafTypeName} leaf ID ${id}, but its RVA could not be mapped to a file offset.`
      ]
    };
  }
  if (record.size <= 0) {
    return {
      data: null,
      issues: [
        `${groupTypeName} references ${leafTypeName} leaf ID ${id}, but the leaf payload size is zero.`
      ]
    };
  }
  const data = new Uint8Array(await file.slice(offset, offset + record.size).arrayBuffer());
  const issues = data.byteLength < record.size
    ? [`${groupTypeName} references ${leafTypeName} leaf ID ${id}, but the leaf payload is truncated.`]
    : undefined;
  return { data: data.byteLength ? data : null, ...(issues ? { issues } : {}) };
};

const readResourceLeafBytes = async (
  file: File,
  tree: ResourceTree,
  langEntry: ResourceLangWithPreview
): Promise<LoadedResourceLeaf> => {
  const offset = tree.rvaToOff(langEntry.dataRVA);
  if (offset == null) {
    return {
      data: null,
      issues: ["Resource RVA could not be mapped to a file offset."]
    };
  }
  const data = new Uint8Array(await file.slice(offset, offset + langEntry.size).arrayBuffer());
  const issues = data.byteLength < langEntry.size
    ? ["Resource preview read fewer bytes than the declared data size."]
    : undefined;
  return { data: data.byteLength ? data : null, ...(issues ? { issues } : {}) };
};

const decodeSpecificResourcePreview = async (
  data: Uint8Array,
  typeName: string,
  entryId: number | null,
  codePage: number | undefined,
  lang: number | null | undefined,
  loadIconLeafData: LoadResourceLeafData,
  loadCursorLeafData: LoadResourceLeafData
): Promise<ResourcePreviewResult | null> => {
  switch (typeName) {
    case "ICON":
      return runSyncPreviewDecoder(() => addIconPreview(data, typeName));
    case "GROUP_ICON":
      return runAsyncPreviewDecoder(() => addGroupIconPreview(data, typeName, loadIconLeafData, lang));
    case "CURSOR":
      return runSyncPreviewDecoder(() => addCursorPreview(data, typeName));
    case "GROUP_CURSOR":
      return runAsyncPreviewDecoder(() => addGroupCursorPreview(data, typeName, loadCursorLeafData, lang));
    case "BITMAP":
      return runSyncPreviewDecoder(() => addBitmapPreview(data, typeName));
    case "MANIFEST":
      return runSyncPreviewDecoder(() => addManifestPreview(data, typeName, codePage));
    case "HTML":
      return runSyncPreviewDecoder(() => addHtmlPreview(data, typeName, codePage));
    case "VERSION":
      return runSyncPreviewDecoder(() => addVersionPreview(data, typeName));
    case "STRING":
      return runSyncPreviewDecoder(() => addStringTablePreview(data, typeName, entryId));
    case "DIALOG":
      return runSyncPreviewDecoder(() => addDialogPreview(data, typeName));
    case "MENU":
      return runSyncPreviewDecoder(() => addMenuPreview(data, typeName));
    case "ACCELERATOR":
      return runSyncPreviewDecoder(() => addAcceleratorPreview(data, typeName));
    case "MESSAGETABLE":
      return runSyncPreviewDecoder(() => addMessageTableResourcePreview(data, typeName, codePage));
    default:
      return null;
  }
};

const decodeResourceLeafPreview = async (
  file: File,
  tree: ResourceTree,
  groupTypeName: string,
  entryId: number | null,
  langEntry: ResourceLangWithPreview,
  loadIconLeafData: LoadResourceLeafData,
  loadCursorLeafData: LoadResourceLeafData
): Promise<ResourcePreviewResult> => {
  if (!langEntry.size || !langEntry.dataRVA) return {};
  try {
    const leaf = await readResourceLeafBytes(file, tree, langEntry);
    if (!leaf.data?.length) return leaf.issues?.length ? { issues: leaf.issues } : {};
    const leafData = leaf.data;
    const typedPreview = await decodeSpecificResourcePreview(
      leafData,
      groupTypeName,
      entryId,
      langEntry.codePage,
      langEntry.lang,
      loadIconLeafData,
      loadCursorLeafData
    );
    if (typedPreview?.preview) {
      const issues = combineIssues(leaf.issues, typedPreview.issues);
      return {
        preview: typedPreview.preview,
        ...(issues ? { issues } : {})
      };
    }
    const heuristicPreview = await runAsyncPreviewDecoder(() =>
      addHeuristicResourcePreview(leafData, langEntry.codePage)
    );
    const issues = combineIssues(leaf.issues, typedPreview?.issues, heuristicPreview?.issues);
    return {
      ...(heuristicPreview?.preview ? { preview: heuristicPreview.preview } : {}),
      ...(issues ? { issues } : {})
    };
  } catch {
    return { issues: ["Resource bytes could not be read for preview."] };
  }
};

const decodeDetailPreviews = async (
  file: File,
  tree: ResourceTree,
  detail: ResourceDetailGroup[],
  loadIconLeafData: LoadResourceLeafData,
  loadCursorLeafData: LoadResourceLeafData
): Promise<ResourceGroupPreviewDecode[]> =>
  Promise.all(detail.map(group =>
    Promise.all(group.entries.map(entry =>
      Promise.all(entry.langs.map(langEntry =>
        decodeResourceLeafPreview(
          file,
          tree,
          group.typeName,
          entry.id,
          langEntry as ResourceLangWithPreview,
          loadIconLeafData,
          loadCursorLeafData
        )
      ))
    ))
  ));

const attachLangPreview = (
  langEntry: ResourceLangWithPreview,
  decoded: ResourcePreviewResult
): ResourceLangWithPreview => ({
  ...langEntry,
  ...(decoded.preview || {}),
  ...(decoded.issues?.length ? { previewIssues: decoded.issues } : {})
});

const attachDetailPreviews = (
  detail: ResourceDetailGroup[],
  decodedGroups: ResourceGroupPreviewDecode[]
): ResourceDetailGroup[] =>
  detail.map((group, groupIndex) => ({
    ...group,
    entries: group.entries.map((entry, entryIndex) => ({
      ...entry,
      langs: entry.langs.map((langEntry, langIndex) =>
        attachLangPreview(
          langEntry as ResourceLangWithPreview,
          decodedGroups[groupIndex]?.[entryIndex]?.[langIndex] || {}
        )
      )
    }))
  }));

export async function enrichResourcePreviews(
  file: File,
  tree: ResourceTree
): Promise<{ top: ResourceTree["top"]; detail: ResourceDetailGroup[]; issues?: string[] }> {
  const detail = tree.detail as ResourceDetailGroup[];
  const iconIndex = buildResourceLeafIndex(detail, "ICON");
  const cursorIndex = buildResourceLeafIndex(detail, "CURSOR");
  const loadIconLeafData = createGroupLeafLoader(file, tree, iconIndex, "GROUP_ICON", "ICON");
  const loadCursorLeafData = createGroupLeafLoader(file, tree, cursorIndex, "GROUP_CURSOR", "CURSOR");
  const decodedGroups = await decodeDetailPreviews(
    file,
    tree,
    detail,
    loadIconLeafData,
    loadCursorLeafData
  );
  const issues = [...(tree.issues || [])];
  return {
    top: tree.top,
    detail: attachDetailPreviews(detail, decodedGroups),
    ...(issues.length ? { issues } : {})
  };
}
