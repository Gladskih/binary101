"use strict";

import {
  describeManifestXmlParserThrow,
  parseBrowserManifestXmlDocument,
  readManifestParserIssue,
  type ManifestXmlDocument,
  type ManifestXmlDocumentParser,
  type ManifestXmlElement
} from "./manifest-xml.js";
import { getXmlLocalTagName, parseXmlTree } from "./xml-tree.js";
import { isAsciiPlaceholderPayload } from "./mui-placeholder.js";
import { decodeTextResource } from "./text.js";
import type {
  ResourceManifestPreview,
  ResourcePreviewResult,
  ResourceXmlTreeNode
} from "./types.js";
import type { MuiResourceConfiguration } from "../mui-config.js";
import { addMissingManifestNamespaceDeclarations } from "./manifest-namespace-fallback.js";

const normalizeText = (value: string | null | undefined): string | null => {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
};

const normalizeBooleanAttribute = (
  value: string | null,
  attributeName: string,
  issues: string[]
): boolean | null => {
  const normalized = normalizeText(value)?.toLowerCase();
  if (!normalized) return null;
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  issues.push(`Manifest ${attributeName}="${value}" is not a recognized boolean value.`);
  return null;
};

const createElementIndex = (doc: ManifestXmlDocument): Map<string, ManifestXmlElement[]> => {
  const index = new Map<string, ManifestXmlElement[]>();
  for (const element of Array.from(doc.getElementsByTagName("*"))) {
    const localName = getXmlLocalTagName(element.tagName);
    const elements = index.get(localName) || [];
    elements.push(element);
    index.set(localName, elements);
  }
  return index;
};

const readFirstElementAttribute = (
  elementsByLocalName: Map<string, ManifestXmlElement[]>,
  localName: string,
  attributeName: string
): string | null =>
  normalizeText(elementsByLocalName.get(localName)?.[0]?.getAttribute(attributeName));

const parseSupportedArchitectures = (
  elementsByLocalName: Map<string, ManifestXmlElement[]>,
  issues: string[]
): string[] => {
  const element = elementsByLocalName.get("supportedarchitectures")?.[0];
  if (!element) return [];
  const values = (element.textContent || "").trim().split(/\s+/).filter(Boolean);
  if (!values.length) {
    issues.push("Manifest supportedArchitectures element is present but empty.");
    return [];
  }
  return [...new Set(values)];
};

const parseManifestInfo = (
  doc: ManifestXmlDocument,
  issues: string[]
): ResourceManifestPreview | null => {
  const elementsByLocalName = createElementIndex(doc);
  const manifestVersion = readFirstElementAttribute(elementsByLocalName, "assembly", "manifestVersion");
  const assemblyType = readFirstElementAttribute(elementsByLocalName, "assemblyidentity", "type");
  const assemblyName = readFirstElementAttribute(elementsByLocalName, "assemblyidentity", "name");
  const assemblyVersion = readFirstElementAttribute(elementsByLocalName, "assemblyidentity", "version");
  const processorArchitecture = readFirstElementAttribute(
    elementsByLocalName,
    "assemblyidentity",
    "processorArchitecture"
  );
  const requestedExecutionLevel = readFirstElementAttribute(
    elementsByLocalName,
    "requestedexecutionlevel",
    "level"
  );
  const requestedUiAccess = normalizeBooleanAttribute(
    readFirstElementAttribute(elementsByLocalName, "requestedexecutionlevel", "uiAccess"),
    "uiAccess",
    issues
  );
  const supportedArchitectures = parseSupportedArchitectures(elementsByLocalName, issues);
  if (
    !manifestVersion &&
    !assemblyType &&
    !assemblyName &&
    !assemblyVersion &&
    !processorArchitecture &&
    !requestedExecutionLevel &&
    requestedUiAccess == null &&
    !supportedArchitectures.length
  ) {
    return null;
  }
  return {
    manifestVersion,
    assemblyType,
    assemblyName,
    assemblyVersion,
    processorArchitecture,
    requestedExecutionLevel,
    requestedUiAccess,
    supportedArchitectures
  };
};

const parseWithManifestNamespaceFallback = (
  text: string,
  parseXmlDocument: ManifestXmlDocumentParser
): ManifestXmlDocument | null => {
  const patchedText = addMissingManifestNamespaceDeclarations(text);
  if (!patchedText) return null;
  try {
    const doc = parseXmlDocument(patchedText);
    return readManifestParserIssue(doc) ? null : doc;
  } catch {
    return null;
  }
};

const parseManifestPreviewDocument = (
  doc: ManifestXmlDocument,
  issues: string[]
): { manifestInfo: ResourceManifestPreview | null; manifestTree: ResourceXmlTreeNode | null } => ({
  manifestInfo: parseManifestInfo(doc, issues),
  manifestTree: parseXmlTree(doc)
});

export function addMuiManifestPlaceholderPreview(
  data: Uint8Array,
  typeName: string,
  muiResourceConfiguration: MuiResourceConfiguration | null
): ResourcePreviewResult | null {
  if (typeName !== "MANIFEST" || !muiResourceConfiguration || !isAsciiPlaceholderPayload(data)) {
    return null;
  }
  return {
    preview: {
      previewKind: "text",
      textPreview: "placeholder"
    }
  };
}

export function addManifestPreviewWithXmlParser(
  data: Uint8Array,
  typeName: string,
  codePage: number | undefined,
  parseXmlDocument: ManifestXmlDocumentParser
): ResourcePreviewResult | null {
  if (typeName !== "MANIFEST") return null;
  const issues: string[] = [];
  const { text, error, terminated } = decodeTextResource(data, codePage);
  if (error) issues.push("Manifest text could not be fully decoded.");
  if (!text) return issues.length ? { issues } : null;
  if (terminated) issues.push("Manifest preview stopped at a NUL terminator before the declared data size.");
  let manifestInfo: ResourceManifestPreview | null = null;
  let manifestTree: ResourceXmlTreeNode | null = null;
  try {
    const doc = parseXmlDocument(text);
    const parserIssue = readManifestParserIssue(doc);
    if (parserIssue) issues.push(parserIssue);
    ({ manifestInfo, manifestTree } = parseManifestPreviewDocument(doc, issues));
    const fallbackDoc = parserIssue ? parseWithManifestNamespaceFallback(text, parseXmlDocument) : null;
    if (fallbackDoc && (!manifestInfo || !manifestTree)) {
      ({ manifestInfo, manifestTree } = parseManifestPreviewDocument(fallbackDoc, issues));
    }
  } catch (error) {
    issues.push(describeManifestXmlParserThrow(error));
    const fallbackDoc = parseWithManifestNamespaceFallback(text, parseXmlDocument);
    if (fallbackDoc) {
      ({ manifestInfo, manifestTree } = parseManifestPreviewDocument(fallbackDoc, issues));
    }
  }
  const uniqueIssues = [...new Set(issues)];
  return {
    preview: {
      previewKind: "text",
      textPreview: text,
      ...(manifestInfo ? { manifestInfo } : {}),
      ...(manifestTree ? { manifestTree } : {})
    },
    ...(uniqueIssues.length ? { issues: uniqueIssues } : {})
  };
}

export function addManifestPreview(
  data: Uint8Array,
  typeName: string,
  codePage: number | undefined
): ResourcePreviewResult | null {
  return addManifestPreviewWithXmlParser(
    data,
    typeName,
    codePage,
    parseBrowserManifestXmlDocument
  );
}
