"use strict";

import {
  describeManifestXmlParserThrow,
  parseBrowserManifestXmlDocument,
  readManifestParserIssue,
  type ManifestXmlDocument,
  type ManifestXmlAttribute,
  type ManifestXmlDocumentParser,
  type ManifestXmlNode,
  type ManifestXmlElement
} from "./manifest-xml.js";
import { decodeTextResource } from "./text.js";
import type {
  ResourceManifestPreview,
  ResourceManifestTreeAttribute,
  ResourceManifestTreeNode,
  ResourcePreviewResult
} from "./types.js";

const XML_ELEMENT_NODE = 1;
const XML_TEXT_NODE = 3;
const XML_CDATA_SECTION_NODE = 4;

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

const getLocalTagName = (tagName: string): string => {
  const localName = tagName.split(":").pop();
  return (localName || tagName).toLowerCase();
};

const normalizeNodeText = (node: ManifestXmlNode): string | null => normalizeText(node.nodeValue);

const createElementIndex = (doc: ManifestXmlDocument): Map<string, ManifestXmlElement[]> => {
  const index = new Map<string, ManifestXmlElement[]>();
  for (const element of Array.from(doc.getElementsByTagName("*"))) {
    const localName = getLocalTagName(element.tagName);
    const elements = index.get(localName) || [];
    elements.push(element);
    index.set(localName, elements);
  }
  return index;
};

const readElementAttributes = (
  element: ManifestXmlElement
): ResourceManifestTreeAttribute[] =>
  Array.from(element.attributes || [])
    .map((attribute: ManifestXmlAttribute) => ({
      name: attribute.name,
      value: attribute.value
    }))
    .filter(attribute => attribute.name);

const buildManifestTreeNode = (element: ManifestXmlElement): ResourceManifestTreeNode => {
  const children: ResourceManifestTreeNode[] = [];
  const textSegments: string[] = [];
  for (const childNode of Array.from(element.childNodes || [])) {
    if (childNode.nodeType === XML_ELEMENT_NODE) {
      children.push(buildManifestTreeNode(childNode as ManifestXmlElement));
      continue;
    }
    if (childNode.nodeType === XML_TEXT_NODE || childNode.nodeType === XML_CDATA_SECTION_NODE) {
      const text = normalizeNodeText(childNode);
      if (text) textSegments.push(text);
    }
  }
  return {
    name: element.tagName,
    attributes: readElementAttributes(element),
    text: textSegments.length ? textSegments.join(" ") : null,
    children
  };
};

const parseManifestTree = (doc: ManifestXmlDocument): ResourceManifestTreeNode | null => {
  const root = doc.documentElement;
  if (!root) return null;
  if (getLocalTagName(root.tagName) === "parsererror") return null;
  return buildManifestTreeNode(root);
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
  let manifestTree: ResourceManifestTreeNode | null = null;
  try {
    const doc = parseXmlDocument(text);
    const parserIssue = readManifestParserIssue(doc);
    if (parserIssue) issues.push(parserIssue);
    manifestInfo = parseManifestInfo(doc, issues);
    manifestTree = parseManifestTree(doc);
  } catch (error) {
    issues.push(describeManifestXmlParserThrow(error));
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
