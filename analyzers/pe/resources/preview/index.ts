"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import { addBitmapPreview } from "./bitmap.js";
import { addCursorPreview, addGroupCursorPreview } from "./cursor.js";
import { addDialogPreview } from "./dialog.js";
import { addAcceleratorPreview } from "./accelerator.js";
import { buildResourceLeafIndex } from "./leaf-index.js";
import { createGroupLeafLoader, readResourceLeafBytes } from "./leaf-data.js";
import { addGroupIconPreview, addIconPreview, type LoadResourceLeafData } from "./icon.js";
import { addMenuPreview } from "./menu.js";
import { addHeuristicResourcePreview } from "./sniff.js";
import { addHtmlPreview, addStringTablePreview } from "./text.js";
import { addMuiManifestPlaceholderPreview, addManifestPreviewWithXmlParser } from "./manifest.js";
import {
  parseBrowserManifestXmlDocument,
  type ManifestXmlDocumentParser
} from "./manifest-xml.js";
import {
  addDialogIncludePreview,
  addFontDirectoryPreview,
  addFontPreview,
  addPlugPlayPreview,
  addRcDataPreview,
  addVxdPreview
} from "./standard-types.js";
import { addRegInstPreview } from "./inf.js";
import { addTypeLibraryPreview } from "./type-library.js";
import { addXmlResourcePreviewWithParser } from "./xml.js";
import { addAniCursorPreview, addAniIconPreview } from "./ani.js";
import { addVersionPreview } from "./version.js";
import { addMessageTableResourcePreview } from "./message-table.js";
import { addMuiConfigPreview, createMuiConfigPreview } from "./mui-config.js";
import { readMuiResource, type MuiResourceCandidate } from "./mui-resource.js";
import { runAsyncPreviewDecoder, runSyncPreviewDecoder } from "./safe-preview-decoder.js";
import type { MuiResourceConfiguration } from "../mui-config.js";
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

const decodeSpecificResourcePreview = async (
  data: Uint8Array,
  typeName: string,
  entryId: number | null,
  langEntry: ResourceLangWithPreview,
  loadIconLeafData: LoadResourceLeafData,
  loadCursorLeafData: LoadResourceLeafData,
  muiResource: MuiResourceCandidate | null,
  parseManifestXmlDocument: ManifestXmlDocumentParser
): Promise<ResourcePreviewResult | null> => {
  switch (typeName) {
    case "ICON":
      return runSyncPreviewDecoder(() => addIconPreview(data, typeName));
    case "GROUP_ICON":
      return runAsyncPreviewDecoder(() =>
        addGroupIconPreview(data, typeName, loadIconLeafData, langEntry.lang)
      );
    case "CURSOR":
      return runSyncPreviewDecoder(() => addCursorPreview(data, typeName));
    case "GROUP_CURSOR":
      return runAsyncPreviewDecoder(() =>
        addGroupCursorPreview(data, typeName, loadCursorLeafData, langEntry.lang)
      );
    case "BITMAP":
      return runSyncPreviewDecoder(() => addBitmapPreview(data, typeName));
    case "MUI":
      return runSyncPreviewDecoder(() => addMuiConfigPreview(data, typeName));
    case "REGINST":
      return runSyncPreviewDecoder(() => addRegInstPreview(data, typeName, langEntry.codePage));
    case "TYPELIB":
      return runSyncPreviewDecoder(() =>
        addTypeLibraryPreview(data, typeName, muiResource?.result.configuration ?? null)
      );
    case "XMLFILE":
    case "UIFILE":
      return runSyncPreviewDecoder(() =>
        addXmlResourcePreviewWithParser(data, typeName, langEntry.codePage, parseManifestXmlDocument)
      );
    case "MANIFEST":
      return runSyncPreviewDecoder(() => (
        addMuiManifestPlaceholderPreview(
          data,
          typeName,
          muiResource?.result.configuration ?? null
        ) ||
        addManifestPreviewWithXmlParser(
          data,
          typeName,
          langEntry.codePage,
          parseManifestXmlDocument
        )
      ));
    case "HTML":
      return runSyncPreviewDecoder(() => addHtmlPreview(data, typeName, langEntry.codePage));
    case "RCDATA":
      return runAsyncPreviewDecoder(() => addRcDataPreview(data, typeName, langEntry.codePage));
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
      return runSyncPreviewDecoder(() =>
        addMessageTableResourcePreview(data, typeName, langEntry.codePage)
      );
    case "DLGINCLUDE":
      return runSyncPreviewDecoder(() => addDialogIncludePreview(data, typeName, langEntry.codePage));
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
  reader: FileRangeReader,
  groupTypeName: string,
  entryId: number | null,
  langEntry: ResourceLangWithPreview,
  loadIconLeafData: LoadResourceLeafData,
  loadCursorLeafData: LoadResourceLeafData,
  muiResource: MuiResourceCandidate | null,
  parseManifestXmlDocument: ManifestXmlDocumentParser
): Promise<ResourcePreviewResult> => {
  if (!langEntry.size || !langEntry.dataRVA) return {};
  if (
    groupTypeName === "MUI" &&
    muiResource?.dataRVA === langEntry.dataRVA &&
    muiResource.size === langEntry.size
  ) {
    return createMuiConfigPreview(muiResource.result);
  }
  try {
    const leaf = await readResourceLeafBytes(reader, langEntry);
    if (!leaf.data?.length) return leaf.issues?.length ? { issues: leaf.issues } : {};
    const leafData = leaf.data;
    const typedPreview = await decodeSpecificResourcePreview(
      leafData,
      groupTypeName,
      entryId,
      langEntry,
      loadIconLeafData,
      loadCursorLeafData,
      muiResource,
      parseManifestXmlDocument
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
  reader: FileRangeReader,
  detail: ResourceDetailGroup[],
  loadIconLeafData: LoadResourceLeafData,
  loadCursorLeafData: LoadResourceLeafData,
  muiResource: MuiResourceCandidate | null,
  parseManifestXmlDocument: ManifestXmlDocumentParser
): Promise<ResourceGroupPreviewDecode[]> =>
  Promise.all(detail.map(group =>
    Promise.all(group.entries.map(entry =>
      Promise.all(entry.langs.map(langEntry =>
        decodeResourceLeafPreview(
          reader,
          group.typeName,
          entry.id,
          langEntry as ResourceLangWithPreview,
          loadIconLeafData,
          loadCursorLeafData,
          muiResource,
          parseManifestXmlDocument
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
  reader: FileRangeReader,
  tree: ResourceTree,
  parseManifestXmlDocument: ManifestXmlDocumentParser = parseBrowserManifestXmlDocument
): Promise<{
  top: ResourceTree["top"];
  detail: ResourceDetailGroup[];
  directories?: ResourceTree["directories"];
  paths?: ResourceTree["paths"];
  muiResourceConfiguration?: MuiResourceConfiguration;
  issues?: string[];
}> {
  const detail = tree.detail as ResourceDetailGroup[];
  const iconIndex = buildResourceLeafIndex(detail, "ICON");
  const cursorIndex = buildResourceLeafIndex(detail, "CURSOR");
  const loadIconLeafData = createGroupLeafLoader(reader, iconIndex, "GROUP_ICON", "ICON");
  const loadCursorLeafData = createGroupLeafLoader(
    reader,
    cursorIndex,
    "GROUP_CURSOR",
    "CURSOR"
  );
  const muiResource = await readMuiResource(reader, detail);
  const decodedGroups = await decodeDetailPreviews(
    reader,
    detail,
    loadIconLeafData,
    loadCursorLeafData,
    muiResource,
    parseManifestXmlDocument
  );
  const issues = [...(tree.issues || [])];
  return {
    top: tree.top,
    detail: attachDetailPreviews(detail, decodedGroups),
    ...(tree.directories?.length ? { directories: tree.directories } : {}),
    ...(tree.paths?.length ? { paths: tree.paths } : {}),
    ...(muiResource?.result.configuration
      ? { muiResourceConfiguration: muiResource.result.configuration }
      : {}),
    ...(issues.length ? { issues } : {})
  };
}
