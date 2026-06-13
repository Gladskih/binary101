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
const ROOT_START_TAG_PATTERN =
  /^(?:\s|<\?[\s\S]*?\?>|<!--[\s\S]*?-->|<!(?!-)[^>]*>)*(<(?![!?/])(?:[^"'>]|"[^"]*"|'[^']*')*>)/u;

const findRootStartTag = (text: string): RootStartTag | null => {
  const match = ROOT_START_TAG_PATTERN.exec(text);
  const rootTag = match?.[1];
  return rootTag ? { endOffset: match[0].length - 1, text: rootTag } : null;
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
