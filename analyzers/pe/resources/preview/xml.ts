"use strict";

import {
  describeXmlParserThrow,
  readXmlParserIssue,
  type ManifestXmlDocumentParser
} from "./manifest-xml.js";
import { decodeTextResource } from "./text.js";
import { parseXmlTree } from "./xml-tree.js";
import type { ResourcePreviewResult } from "./types.js";

const looksLikeXmlText = (text: string): boolean => text.trimStart().startsWith("<");

const buildXmlSummaryPreview = (typeName: string, dataLength: number): ResourcePreviewResult => ({
  preview: {
    previewKind: "summary",
    previewFields: [
      { label: "Type", value: typeName },
      { label: "Size", value: `${dataLength} bytes` },
      { label: "Note", value: "Named XML/UI resource payload was not plain XML text." }
    ]
  }
});

export function addXmlResourcePreviewWithParser(
  data: Uint8Array,
  typeName: string,
  codePage: number | undefined,
  parseXmlDocument: ManifestXmlDocumentParser
): ResourcePreviewResult | null {
  if (typeName !== "XMLFILE" && typeName !== "UIFILE") return null;
  const issues: string[] = [];
  const { text, error, encoding, terminated } = decodeTextResource(data, codePage);
  if (error) issues.push(`${typeName} text could not be fully decoded.`);
  if (!text || !looksLikeXmlText(text)) return buildXmlSummaryPreview(typeName, data.length);
  if (terminated) issues.push(`${typeName} preview stopped at a NUL terminator before the declared data size.`);
  try {
    const doc = parseXmlDocument(text);
    const parserIssue = readXmlParserIssue(doc, typeName);
    if (parserIssue) issues.push(parserIssue);
    const xmlTree = parseXmlTree(doc);
    return {
      preview: {
        previewKind: "xml",
        textPreview: text,
        ...(encoding ? { textEncoding: encoding } : {}),
        ...(xmlTree ? { xmlTree } : {}),
        previewFields: [
          { label: "Type", value: typeName },
          { label: "Format", value: "XML text" }
        ]
      },
      ...(issues.length ? { issues: [...new Set(issues)] } : {})
    };
  } catch (error) {
    return {
      preview: {
        previewKind: "xml",
        textPreview: text,
        ...(encoding ? { textEncoding: encoding } : {}),
        previewFields: [
          { label: "Type", value: typeName },
          { label: "Format", value: "XML text" }
        ]
      },
      issues: [...new Set([...issues, describeXmlParserThrow(error, typeName)])]
    };
  }
}
