"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import { addBitmapPreview } from "./bitmap.js";
import { addCursorPreview, addGroupCursorPreview } from "./cursor.js";
import { addDialogPreview } from "./dialog.js";
import { addDialogInitPreview } from "./dialog-init.js";
import { addDialogLayoutPreview } from "./dialog-layout.js";
import { addToolbarPreview } from "./toolbar.js";
import { addFontDirectoryPreview } from "./font-directory.js";
import { validateFontReferences } from "./font-reference-validation.js";
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
  addFontPreview,
  addPlugPlayPreview,
  addRcDataPreview,
  addVxdPreview
} from "./standard-types.js";
import { addRegInstPreview } from "./inf.js";
import { createRegistryResourceReader } from "./registry-resource.js";
import { addTypeLibraryPreview } from "./type-library.js";
import { addXmlResourcePreviewWithParser } from "./xml.js";
import { addWevtTemplatePreview } from "./wevt-template.js";
import { linkWevtMessages } from "./wevt-message-links.js";
import { addAniCursorPreview, addAniIconPreview } from "./ani.js";
import { addVersionPreview } from "./version.js";
import { addMessageTableResourcePreview } from "./message-table.js";
import { addMuiConfigPreview, createMuiConfigPreview } from "./mui-config.js";
import { readMuiResource, type MuiResourceCandidate } from "./mui-resource.js";
import { runAsyncPreviewDecoder } from "./safe-preview-decoder.js";
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

const isRegistryResource = (typeName: string): boolean =>
  ["REGISTRY", "RGS"].includes(typeName.toUpperCase());

const matchesMuiResource = (
  typeName: string, entry: ResourceLangWithPreview, resource: MuiResourceCandidate | null
): resource is MuiResourceCandidate => typeName === "MUI" && resource !== null &&
  resource.dataRVA === entry.dataRVA && resource.size === entry.size;

const withLeafIssues = (
  leafIssues: string[] | undefined, result: ResourcePreviewResult
): ResourcePreviewResult => {
  const issues = combineIssues(leafIssues, result.issues);
  return { ...result, ...(issues ? { issues } : {}) };
};

const finishResourcePreview = async (
  data: Uint8Array, leafIssues: string[] | undefined,
  typed: ResourcePreviewResult | null, codePage: number | undefined
): Promise<ResourcePreviewResult> => {
  if (typed?.preview) return withLeafIssues(leafIssues, typed);
  const heuristic = await runAsyncPreviewDecoder(() => addHeuristicResourcePreview(data, codePage));
  return withLeafIssues(combineIssues(leafIssues, typed?.issues), heuristic ?? {});
};

const simplePreviewDecoders = new Map<string,
  (data: Uint8Array, typeName: string) => ResourcePreviewResult | null | Promise<ResourcePreviewResult | null>
>([
  ["ICON", addIconPreview], ["CURSOR", addCursorPreview], ["BITMAP", addBitmapPreview],
  ["MUI", addMuiConfigPreview], ["VERSION", addVersionPreview], ["DIALOG", addDialogPreview],
  ["DLGINIT", addDialogInitPreview], ["AFX_DIALOG_LAYOUT", addDialogLayoutPreview],
  ["TOOLBAR", addToolbarPreview], ["FONTDIR", addFontDirectoryPreview],
  ["WEVT_TEMPLATE", addWevtTemplatePreview],
  ["FONT", addFontPreview], ["MENU", addMenuPreview], ["ACCELERATOR", addAcceleratorPreview],
  ["PLUGPLAY", addPlugPlayPreview], ["VXD", addVxdPreview],
  ["ANICURSOR", addAniCursorPreview], ["ANIICON", addAniIconPreview]
]);

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
  const simple = simplePreviewDecoders.get(typeName);
  if (simple) return runAsyncPreviewDecoder(async () => simple(data, typeName));
  const decoders = new Map<string, () => ResourcePreviewResult | null | Promise<ResourcePreviewResult | null>>([
    ["GROUP_ICON", () => addGroupIconPreview(data, typeName, loadIconLeafData, langEntry.lang)],
    ["GROUP_CURSOR", () => addGroupCursorPreview(data, typeName, loadCursorLeafData, langEntry.lang)],
    ["REGINST", () => addRegInstPreview(data, typeName, langEntry.codePage)],
    ["TYPELIB", () => addTypeLibraryPreview(data, typeName, muiResource?.result.configuration ?? null)],
    ["XMLFILE", () => addXmlResourcePreviewWithParser(
      data, typeName, langEntry.codePage, parseManifestXmlDocument)],
    ["UIFILE", () => addXmlResourcePreviewWithParser(
      data, typeName, langEntry.codePage, parseManifestXmlDocument)],
    ["RIBBON_XML", () => addXmlResourcePreviewWithParser(
      data, typeName, langEntry.codePage, parseManifestXmlDocument)],
    ["MANIFEST", () => addMuiManifestPlaceholderPreview(
      data, typeName, muiResource?.result.configuration ?? null) || addManifestPreviewWithXmlParser(
      data, typeName, langEntry.codePage, parseManifestXmlDocument)],
    ["HTML", () => addHtmlPreview(data, typeName, langEntry.codePage)],
    ["RCDATA", () => addRcDataPreview(data, typeName, langEntry.codePage)],
    ["STRING", () => addStringTablePreview(data, typeName, entryId)],
    ["MESSAGETABLE", () => addMessageTableResourcePreview(data, typeName, langEntry.codePage)],
    ["DLGINCLUDE", () => addDialogIncludePreview(data, typeName, langEntry.codePage)]
  ]);
  const decode = decoders.get(typeName);
  return decode ? runAsyncPreviewDecoder(async () => decode()) : null;
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
  if (matchesMuiResource(groupTypeName, langEntry, muiResource)) {
    return createMuiConfigPreview(muiResource.result);
  }
  try {
    const leaf = await readResourceLeafBytes(reader, langEntry);
    if (!leaf.data?.length) return { issues: leaf.issues ?? [] };
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
    return await finishResourcePreview(leafData, leaf.issues, typedPreview, langEntry.codePage);
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
): Promise<ResourceGroupPreviewDecode[]> => {
  const readRegistry = createRegistryResourceReader(reader);
  return Promise.all(detail.map(group =>
    Promise.all(group.entries.map(entry =>
      Promise.all(entry.langs.map(langEntry =>
        isRegistryResource(group.typeName) ||
          (group.typeName === "RCDATA" && entry.name?.toLowerCase().endsWith(".rgs"))
          ? readRegistry(langEntry as ResourceLangWithPreview)
          : decodeResourceLeafPreview(
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
};

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
    detail: linkWevtMessages(validateFontReferences(attachDetailPreviews(detail, decodedGroups))),
    ...(tree.directories?.length ? { directories: tree.directories } : {}),
    ...(tree.paths?.length ? { paths: tree.paths } : {}),
    ...(muiResource?.result.configuration
      ? { muiResourceConfiguration: muiResource.result.configuration }
      : {}),
    ...(issues.length ? { issues } : {})
  };
}
