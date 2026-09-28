"use strict";

import {
  describeXmlParserThrow,
  readXmlParserIssue,
  type ManifestXmlDocumentParser
} from "./manifest-xml.js";
import { decodeTextResource } from "./text.js";
import { parseXmlTree } from "./xml-tree.js";
import { parseRibbonBml } from "./ribbon-bml.js";
import type { ResourcePreviewResult } from "./types.js";

const looksLikeXmlText = (text: string): boolean => text.trimStart().startsWith("<");

const isCompiledRibbon = (data: Uint8Array): boolean =>
  // new.ksy: nine-byte preamble, five-byte ASCII "SCBin", then LE u32 size at offset 14.
  // https://github.com/DarkShadow44/UIRibbon-Reversing/blob/master/new.ksy
  data.length >= 14 && [0, 18, 0, 0, 0, 0, 0, 1, 0, 83, 67, 66, 105, 110]
    .every((byte, index) => data[index] === byte);

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
  if (!["XMLFILE", "UIFILE", "RIBBON_XML"].includes(typeName)) return null;
  if (typeName === "UIFILE" && isCompiledRibbon(data)) {
    const issues: string[] = [];
    const ribbonBml = parseRibbonBml(data, issues);
    return { preview: { previewKind: "summary", previewFields: [
      { label: "Type", value: typeName },
      { label: "Format", value: "Windows Ribbon compiled BML" },
      { label: "Size", value: `${data.length} bytes` }
    ], ...(ribbonBml ? { ribbonBml } : {}) }, ...(issues.length ? { issues } : {}) };
  }
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
        previewKind: typeName === "RIBBON_XML" ? "ribbonXml" : "xml",
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
        previewKind: typeName === "RIBBON_XML" ? "ribbonXml" : "xml",
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
