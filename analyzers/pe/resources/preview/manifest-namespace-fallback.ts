"use strict";

// Microsoft Learn, "Manifest File Schema":
// https://learn.microsoft.com/en-us/windows/win32/sbscs/manifest-file-schema
const KNOWN_MANIFEST_NAMESPACES: Array<readonly [string, string]> = [
  ["asmv1", "urn:schemas-microsoft-com:asm.v1"],
  ["asmv2", "urn:schemas-microsoft-com:asm.v2"],
  ["asmv3", "urn:schemas-microsoft-com:asm.v3"]
];

type RootStartTag = {
  endOffset: number;
  text: string;
};

// XML 1.0 permits declarations, comments, processing instructions, doctypes, and whitespace
// before the document element. Source: https://www.w3.org/TR/xml/#sec-prolog-dtd
const PROCESSING_INSTRUCTION_START = "<?";
const XML_COMMENT_START = "<!--";
const DECLARATION_START = "<!";
const TAG_OPEN = "<";
const TAG_CLOSE = ">";

const skipClosedToken = (
  text: string,
  offset: number,
  openingToken: string,
  closingToken: string
): number | null => {
  const closingOffset = text.indexOf(closingToken, offset + openingToken.length);
  return closingOffset === -1 ? null : closingOffset + closingToken.length;
};

const skipWhitespace = (text: string, offset: number): number => {
  let nextOffset = offset;
  while (nextOffset < text.length) {
    const character = text[nextOffset];
    if (character === undefined || character.trim() !== "") return nextOffset;
    nextOffset += 1;
  }
  return nextOffset;
};

const skipDeclaration = (text: string, offset: number): number | null => {
  const closingOffset = text.indexOf(TAG_CLOSE, offset + DECLARATION_START.length);
  return closingOffset === -1 ? null : closingOffset + TAG_CLOSE.length;
};

const skipPrologItem = (text: string, offset: number): number | null => {
  if (text.startsWith(PROCESSING_INSTRUCTION_START, offset)) {
    return skipClosedToken(text, offset, PROCESSING_INSTRUCTION_START, "?>");
  }
  if (text.startsWith(XML_COMMENT_START, offset)) {
    return skipClosedToken(text, offset, XML_COMMENT_START, "-->");
  }
  if (text.startsWith(DECLARATION_START, offset)) {
    if (text[offset + DECLARATION_START.length] === "-") return null;
    return skipDeclaration(text, offset);
  }
  return offset;
};

const skipXmlProlog = (text: string): number | null => {
  let offset = 0;
  while (offset < text.length) {
    const contentOffset = skipWhitespace(text, offset);
    const nextOffset = skipPrologItem(text, contentOffset);
    if (nextOffset === null || nextOffset === contentOffset) return nextOffset;
    offset = nextOffset;
  }
  return offset;
};

const findRootTagEndOffset = (text: string, offset: number): number | null => {
  let nextOffset = offset + TAG_OPEN.length;
  let quotedAttributeDelimiter: string | null = null;
  while (nextOffset < text.length) {
    const character = text[nextOffset];
    if (character === undefined) return null;
    if (quotedAttributeDelimiter !== null && character === quotedAttributeDelimiter) {
      quotedAttributeDelimiter = null;
    } else if (quotedAttributeDelimiter === null && (character === "\"" || character === "'")) {
      quotedAttributeDelimiter = character;
    } else if (quotedAttributeDelimiter === null && character === TAG_CLOSE) {
      return nextOffset;
    }
    nextOffset += 1;
  }
  return null;
};

const findRootStartTag = (text: string): RootStartTag | null => {
  const offset = skipXmlProlog(text);
  if (offset === null || !text.startsWith(TAG_OPEN, offset)) return null;
  const rootNameStart = text[offset + TAG_OPEN.length];
  if (rootNameStart === undefined || rootNameStart === "!" || rootNameStart === "?") return null;
  if (rootNameStart === "/") return null;
  const endOffset = findRootTagEndOffset(text, offset);
  return endOffset === null ? null : { endOffset, text: text.slice(offset, endOffset + 1) };
};

const usesPrefix = (text: string, prefix: string): boolean =>
  text.includes(`<${prefix}:`) || text.includes(`</${prefix}:`);

const declaresPrefix = (rootTag: string, prefix: string): boolean =>
  new RegExp(`\\sxmlns:${prefix}\\s*=`).test(rootTag);

const missingDeclarations = (text: string, rootTag: string): string =>
  KNOWN_MANIFEST_NAMESPACES
    .filter(([prefix]) => usesPrefix(text, prefix) && !declaresPrefix(rootTag, prefix))
    .map(([prefix, namespace]) => ` xmlns:${prefix}="${namespace}"`)
    .join("");

const selfClosingInsertOffset = (text: string, rootEndOffset: number): number =>
  text.slice(0, rootEndOffset - 1).trimEnd().length;

const insertOffsetForRoot = (text: string, root: RootStartTag): number =>
  root.text.endsWith("/>") ? selfClosingInsertOffset(text, root.endOffset) : root.endOffset;

export const addMissingManifestNamespaceDeclarations = (text: string): string | null => {
  const root = findRootStartTag(text);
  if (!root) return null;
  const declarations = missingDeclarations(text, root.text);
  if (!declarations) return null;
  const insertAt = insertOffsetForRoot(text, root);
  return `${text.slice(0, insertAt)}${declarations}${text.slice(insertAt)}`;
};
