"use strict";

export interface ManifestXmlAttribute {
  name: string;
  value: string;
}

export interface ManifestXmlNode {
  childNodes: ManifestXmlNodeList<ManifestXmlNode>;
  nodeName: string;
  nodeType: number;
  nodeValue: string | null;
  textContent: string | null;
}

export interface ManifestXmlNodeList<TNode = ManifestXmlElement> extends ArrayLike<TNode> {
  item(index: number): TNode | null;
  [index: number]: TNode;
}

export interface ManifestXmlElement extends ManifestXmlNode {
  attributes: ManifestXmlNodeList<ManifestXmlAttribute>;
  getAttribute(name: string): string | null;
  getElementsByTagName(tagName: string): ManifestXmlNodeList;
  tagName: string;
}

export interface ManifestXmlDocument {
  documentElement: ManifestXmlElement | null;
  getElementsByTagName(tagName: string): ManifestXmlNodeList;
}

export type ManifestXmlDocumentParser = (text: string) => ManifestXmlDocument;

export function readManifestParserIssue(doc: ManifestXmlDocument): string | null {
  const parserError = doc.getElementsByTagName("parsererror").item(0);
  if (!parserError) return null;
  const message = (parserError.textContent || "").trim();
  return message
    ? `XML parser reported malformed manifest markup: ${message}`
    : "XML parser reported malformed manifest markup.";
}

export function parseBrowserManifestXmlDocument(text: string): ManifestXmlDocument {
  if (typeof DOMParser === "undefined") {
    throw new Error("DOMParser is not available in this environment.");
  }
  return new DOMParser().parseFromString(text, "application/xml");
}

export function describeManifestXmlParserThrow(error: unknown): string {
  if (error instanceof Error && error.message) {
    return `XML parser threw while reading manifest markup: ${error.message}`;
  }
  return "XML parser threw while reading manifest markup.";
}
