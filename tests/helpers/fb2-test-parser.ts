"use strict";

import { DOMParser as XmlDomParser } from "@xmldom/xmldom";
import { parseFb2WithXmlParser, type Fb2ParseResult } from "../../analyzers/fb2/index.js";
import type { Fb2XmlDocumentParser } from "../../analyzers/fb2/xml.js";

export const parseFb2TestXmlDocument: Fb2XmlDocumentParser = text =>
  new XmlDomParser({ onError: () => {} }).parseFromString(text, "application/xml");

export function parseFb2ForTests(file: File): Promise<Fb2ParseResult | null> {
  return parseFb2WithXmlParser(file, parseFb2TestXmlDocument);
}
