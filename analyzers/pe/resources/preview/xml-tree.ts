"use strict";

import type {
  ManifestXmlAttribute,
  ManifestXmlDocument,
  ManifestXmlElement,
  ManifestXmlNode
} from "./manifest-xml.js";
import type { ResourceXmlTreeAttribute, ResourceXmlTreeNode } from "./types.js";

// DOM nodeType values are fixed by the DOM Standard.
// Source: https://dom.spec.whatwg.org/#node
const XML_ELEMENT_NODE = 1;
const XML_TEXT_NODE = 3;
const XML_CDATA_SECTION_NODE = 4;

const normalizeText = (value: string | null | undefined): string | null => {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
};

const normalizeNodeText = (node: ManifestXmlNode): string | null => normalizeText(node.nodeValue);

export const getXmlLocalTagName = (tagName: string): string => {
  const localName = tagName.split(":").pop();
  return (localName || tagName).toLowerCase();
};

const readElementAttributes = (element: ManifestXmlElement): ResourceXmlTreeAttribute[] =>
  Array.from(element.attributes || [])
    .map((attribute: ManifestXmlAttribute) => ({ name: attribute.name, value: attribute.value }))
    .filter(attribute => attribute.name);

const buildTreeNode = (element: ManifestXmlElement): ResourceXmlTreeNode => {
  const children: ResourceXmlTreeNode[] = [];
  const textSegments: string[] = [];
  for (const childNode of Array.from(element.childNodes || [])) {
    if (childNode.nodeType === XML_ELEMENT_NODE) {
      children.push(buildTreeNode(childNode as ManifestXmlElement));
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

export const parseXmlTree = (doc: ManifestXmlDocument): ResourceXmlTreeNode | null => {
  const root = doc.documentElement;
  if (!root) return null;
  if (getXmlLocalTagName(root.tagName) === "parsererror") return null;
  return buildTreeNode(root);
};
