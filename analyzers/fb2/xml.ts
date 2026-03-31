"use strict";

export interface Fb2XmlNodeList<TNode extends Fb2XmlElement = Fb2XmlElement>
  extends ArrayLike<TNode> {
  item(index: number): TNode | null;
  [index: number]: TNode;
}

export interface Fb2XmlElement {
  getAttribute(name: string): string | null;
  getElementsByTagName(tagName: string): Fb2XmlNodeList;
  textContent: string | null;
}

export interface Fb2XmlDocument {
  getElementsByTagName(tagName: string): Fb2XmlNodeList;
}

export type Fb2XmlDocumentParser = (text: string) => Fb2XmlDocument;

export function readParserIssue(doc: Fb2XmlDocument): string | null {
  const parserError = doc.getElementsByTagName("parsererror").item(0);
  if (!parserError) return null;
  const message = (parserError.textContent || "").trim();
  return message
    ? `XML parser reported malformed FB2 markup: ${message}`
    : "XML parser reported malformed FB2 markup.";
}

export function parseBrowserFb2XmlDocument(text: string): Fb2XmlDocument {
  return new DOMParser().parseFromString(text, "application/xml");
}

export function describeXmlParserThrow(error: unknown): string {
  if (error instanceof Error && error.message) {
    return `XML parser threw while reading FB2 markup: ${error.message}`;
  }
  return "XML parser threw while reading FB2 markup.";
}
