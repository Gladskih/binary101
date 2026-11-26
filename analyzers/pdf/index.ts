import { createFileRangeReader } from "../file-range-reader.js";
import { parseCatalogDictionary, parseInfoDictionary } from "./dictionary.js";
import { readEmbeddedFiles } from "./embedded-files.js";
import { parseHeader, parseStartxref } from "./header.js";
import { readPdfText } from "./object.js";
import { createObjectResolver } from "./object-resolver.js";
import type { PdfObjectResolver } from "./object-resolver.js";
import { readPageTree } from "./page-tree.js";
import { readName } from "./syntax.js";
import type { PdfDictionary } from "./syntax.js";
import { readRevisions } from "./xref.js";
import type { PdfIndirectRef, PdfParseResult } from "./types.js";

const readCatalog = async (
  resolve: PdfObjectResolver, root: PdfIndirectRef | null,
  issues: string[]
): Promise<PdfDictionary | null> => {
  if (!root) {
    issues.push("Trailer lacks a valid /Root reference.");
    return null;
  }
  const object = await resolve.dictionary(root, "Catalog");
  if (!object) return null;
  if (readName(object.fields.get("Type")) !== "Catalog") {
    issues.push("The /Root object is missing /Type /Catalog.");
    return null;
  }
  return object;
};

const readPages = async (
  resolve: PdfObjectResolver, ref: PdfIndirectRef | null, issues: string[]
): Promise<PdfParseResult["pages"]> => {
  if (!ref) {
    issues.push("Catalog lacks a valid /Pages reference.");
    return null;
  }
  const object = await resolve.dictionary(ref, "Pages");
  if (!object) return null;
  if (readName(object.fields.get("Type")) !== "Pages") {
    issues.push("The /Pages object is missing /Type /Pages.");
    return null;
  }
  return readPageTree(resolve, ref, object, issues);
};

const readStructure = async (
  resolve: PdfObjectResolver, root: PdfIndirectRef | null, encrypt: string | null, issues: string[]
): Promise<Pick<PdfParseResult, "catalog" | "pages" | "embeddedFiles">> => {
  const object = await readCatalog(resolve, root, issues);
  if (!object) return { catalog: null, pages: null, embeddedFiles: [] };
  const catalog = parseCatalogDictionary(object);
  return {
    catalog,
    pages: await readPages(resolve, catalog.pagesRef, issues),
    embeddedFiles: await readEmbeddedFiles(resolve, object, encrypt, issues)
  };
};

const findEncryption = (revisions: PdfParseResult["revisions"]): string | null => {
  for (const { primary } of revisions) {
    if (primary.trailer?.encrypt != null) return primary.trailer.encrypt;
  }
  return null;
};

export const parsePdf = async (file: File): Promise<PdfParseResult> => {
  const reader = createFileRangeReader(file, 0, file.size);
  const issues: string[] = [];
  const header = parseHeader(await readPdfText(reader, 0, 1024), issues);
  // Find startxref in a bounded tail window, including room for trailing data.
  const tailLength = 64 * 1024;
  const startxref = parseStartxref(
    await readPdfText(reader, Math.max(0, file.size - tailLength), tailLength), issues);
  const { revisions, index } = await readRevisions(reader, startxref, issues);
  const trailer = revisions[0]?.primary.trailer;
  const encrypt = findEncryption(revisions);
  const resolve = createObjectResolver(reader, index, encrypt, issues);
  if (encrypt != null) {
    issues.push("A trailer declares /Encrypt. Encrypted strings and object streams are unavailable.");
  }
  const info = trailer?.infoRef && encrypt == null ? await resolve.dictionary(trailer.infoRef, "Info") : null;
  const structure = trailer ? await readStructure(resolve, trailer.rootRef, encrypt, issues)
    : { catalog: null, pages: null, embeddedFiles: [] };
  return {
    size: file.size, header, startxref, revisions, ...structure,
    info: info ? parseInfoDictionary(info) : null, issues
  };
};
