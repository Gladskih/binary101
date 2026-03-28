"use strict";

import { addBitmapPreview } from "./bitmap.js";
import { addCursorPreview, addGroupCursorPreview } from "./cursor.js";
import { addDialogPreview } from "./dialog.js";
import { addAcceleratorPreview } from "./accelerator.js";
import { buildResourceLeafIndex } from "./leaf-index.js";
import { createGroupLeafLoader, readResourceLeafBytes } from "./leaf-data.js";
import {
  addGroupIconPreview,
  addIconPreview,
  type LoadResourceLeafData
} from "./icon.js";
import { addMenuPreview } from "./menu.js";
import { addHeuristicResourcePreview } from "./sniff.js";
import {
  addHtmlPreview,
  addManifestPreview,
  addStringTablePreview
} from "./text.js";
import {
  addDialogIncludePreview,
  addFontDirectoryPreview,
  addFontPreview,
  addPlugPlayPreview,
  addRcDataPreview,
  addVxdPreview
} from "./standard-types.js";
import { addAniCursorPreview, addAniIconPreview } from "./ani.js";
import { addVersionPreview } from "./version.js";
import { decodeMessageTablePreview } from "./message-table.js";
import type {
  ResourceDetailGroup,
  ResourceLangWithPreview,
  ResourcePreviewResult
} from "./types.js";
import type { ResourceTree } from "../core.js";

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
    case "RCDATA":
      return runAsyncPreviewDecoder(() => addRcDataPreview(data, typeName, codePage));
    case "VERSION":
      return runSyncPreviewDecoder(() => addVersionPreview(data, typeName));
    case "STRING":
      return runSyncPreviewDecoder(() => addStringTablePreview(data, typeName, entryId));
    case "DIALOG":
      return runSyncPreviewDecoder(() => addDialogPreview(data, typeName));
    case "FONTDIR":
      return runSyncPreviewDecoder(() => addFontDirectoryPreview(data, typeName));
    case "FONT":
      return runAsyncPreviewDecoder(() => addFontPreview(data, typeName));
    case "MENU":
      return runSyncPreviewDecoder(() => addMenuPreview(data, typeName));
    case "ACCELERATOR":
      return runSyncPreviewDecoder(() => addAcceleratorPreview(data, typeName));
    case "MESSAGETABLE":
      return runSyncPreviewDecoder(() => addMessageTableResourcePreview(data, typeName, codePage));
    case "DLGINCLUDE":
      return runSyncPreviewDecoder(() => addDialogIncludePreview(data, typeName, codePage));
    case "PLUGPLAY":
      return runSyncPreviewDecoder(() => addPlugPlayPreview(data, typeName));
    case "VXD":
      return runSyncPreviewDecoder(() => addVxdPreview(data, typeName));
    case "ANICURSOR":
      return runAsyncPreviewDecoder(() => addAniCursorPreview(data, typeName));
    case "ANIICON":
      return runAsyncPreviewDecoder(() => addAniIconPreview(data, typeName));
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
): Promise<{
  top: ResourceTree["top"];
  detail: ResourceDetailGroup[];
  directories?: ResourceTree["directories"];
  paths?: ResourceTree["paths"];
  issues?: string[];
}> {
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
    ...(tree.directories?.length ? { directories: tree.directories } : {}),
    ...(tree.paths?.length ? { paths: tree.paths } : {}),
    ...(issues.length ? { issues } : {})
  };
}
