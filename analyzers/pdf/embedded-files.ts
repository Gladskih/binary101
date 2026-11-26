import { readPdfTextString } from "./dictionary.js";
import type { PdfObjectResolver } from "./object-resolver.js";
import { readArray, readDictionary, readName, readReference, unsigned } from "./syntax.js";
import type { PdfDictionary } from "./syntax.js";
import type { PdfEmbeddedFile, PdfIndirectRef } from "./types.js";

interface FileReference {
  token: string;
  source: string;
  name?: string;
}

interface EmbeddedFileIndex {
  resolve: PdfObjectResolver;
  issues: string[];
  references: FileReference[];
  visited: Set<number>;
  remaining: number;
  truncated: boolean;
}

const dictionaryValue = async (
  resolve: PdfObjectResolver, token: string | undefined, label: string, issues: string[]
): Promise<PdfDictionary | null> => {
  if (token == null || token === "null") return null;
  const ref = readReference(token);
  if (ref) return resolve.dictionary(ref, label);
  const dictionary = readDictionary(token);
  if (dictionary) return dictionary;
  issues.push(label + " is not a dictionary or indirect reference.");
  return null;
};

const appendReference = (index: EmbeddedFileIndex, reference: FileReference): void => {
  if (index.references.length < 512) index.references.push(reference);
  else index.truncated = true;
};

const readNamePairs = (index: EmbeddedFileIndex, token: string): void => {
  const items = readArray(token);
  if (!items || items.length % 2 !== 0) {
    index.issues.push("EmbeddedFiles /Names is not an array of name and file specification pairs.");
    return;
  }
  for (let i = 0; i < items.length && !index.truncated; i += 2) {
    appendReference(index, { token: items[i + 1]!, name: items[i]!, source: "EmbeddedFiles name tree" });
  }
};

const visitNameTree = async (index: EmbeddedFileIndex, token: string, depth: number): Promise<void> => {
  if (depth >= 32 || index.remaining <= 0) {
    index.truncated = true;
    return;
  }
  index.remaining -= 1;
  const ref = readReference(token);
  if (ref && index.visited.has(ref.objectNumber)) {
    index.issues.push("Repeated or cyclic EmbeddedFiles node " + ref.objectNumber + ".");
    return;
  }
  if (ref) index.visited.add(ref.objectNumber);
  const node = await dictionaryValue(index.resolve, token, "EmbeddedFiles node", index.issues);
  if (node) await readNameTreeNode(index, node, depth);
};

const readNameTreeNode = async (
  index: EmbeddedFileIndex, node: PdfDictionary, depth: number
): Promise<void> => {
  // ISO 32000-2, 7.9.6: name-tree leaves use /Names and intermediate nodes use /Kids.
  const names = node.fields.get("Names");
  if (names != null) {
    readNamePairs(index, names);
    return;
  }
  const children = readArray(node.fields.get("Kids"));
  if (!children) {
    index.issues.push("EmbeddedFiles node lacks a valid /Names or /Kids array.");
    return;
  }
  for (const child of children) {
    if (index.truncated) break;
    if (!readReference(child)) {
      index.issues.push("EmbeddedFiles /Kids contains an invalid indirect reference.");
      continue;
    }
    await visitNameTree(index, child, depth + 1);
  }
};

const readAssociatedFiles = (index: EmbeddedFileIndex, token: string | undefined): void => {
  if (token == null || token === "null") return;
  const items = readArray(token);
  if (!items) {
    index.issues.push("Catalog /AF is not an array of file specifications.");
    return;
  }
  for (const item of items) {
    appendReference(index, { token: item, source: "Catalog /AF" });
    if (index.references.length >= 512 && index.truncated) break;
  }
};

const readEmbeddedStream = async (
  index: EmbeddedFileIndex, fields: PdfDictionary["fields"]
): Promise<{ ref: PdfIndirectRef; fields: PdfDictionary["fields"] } | null> => {
  const embedded = await dictionaryValue(index.resolve, fields.get("EF"),
    "File specification /EF", index.issues);
  if (!embedded) return null;
  const ref = readReference(embedded.fields.get("UF")) ?? readReference(embedded.fields.get("F"));
  if (!ref) {
    index.issues.push("File specification /EF lacks a supported /UF or /F stream reference.");
    return null;
  }
  const stream = await index.resolve.streamDictionary(ref, "Embedded file stream");
  if (!stream) return null;
  const type = stream.fields.get("Type");
  if (type != null && type !== "null" && readName(type) !== "EmbeddedFile") {
    index.issues.push("Embedded file stream " + ref.objectNumber + " has an unexpected /Type.");
    return null;
  }
  return { ref, fields: stream.fields };
};

const inspectFile = async (
  index: EmbeddedFileIndex, reference: FileReference, decode: typeof readPdfTextString
): Promise<PdfEmbeddedFile | null> => {
  const spec = await dictionaryValue(index.resolve, reference.token, "File specification", index.issues);
  if (!spec) return null;
  const stream = await readEmbeddedStream(index, spec.fields);
  if (!stream) return null;
  const params = await dictionaryValue(index.resolve, stream.fields.get("Params"),
    "Embedded file /Params", index.issues);
  return {
    fileSpec: readReference(reference.token), stream: stream.ref,
    name: decode(spec.fields.get("UF")) ?? decode(spec.fields.get("F")) ?? decode(reference.name),
    description: decode(spec.fields.get("Desc")),
    mediaType: readName(stream.fields.get("Subtype")),
    decodedSize: unsigned(params?.fields.get("Size")),
    storedSize: unsigned(stream.fields.get("Length")),
    relationship: readName(spec.fields.get("AFRelationship")),
    sources: [reference.source]
  };
};

const inspectReferences = async (
  index: EmbeddedFileIndex, decode: typeof readPdfTextString
): Promise<PdfEmbeddedFile[]> => {
  const files: PdfEmbeddedFile[] = [];
  const byReference = new Map<string, PdfEmbeddedFile | null>();
  for (const reference of index.references) {
    const ref = readReference(reference.token);
    const key = ref ? ref.objectNumber + ":" + ref.generation : reference.token;
    if (byReference.has(key)) {
      const existing = byReference.get(key);
      if (existing && !existing.sources.includes(reference.source)) existing.sources.push(reference.source);
      continue;
    }
    const file = await inspectFile(index, reference, decode);
    byReference.set(key, file);
    if (file) files.push(file);
  }
  return files;
};

export const readEmbeddedFiles = async (
  resolve: PdfObjectResolver, catalog: PdfDictionary, encryption: string | null, issues: string[]
): Promise<PdfEmbeddedFile[]> => {
  const index: EmbeddedFileIndex = {
    resolve, issues, references: [], visited: new Set(), remaining: 512, truncated: false
  };
  const names = await dictionaryValue(resolve, catalog.fields.get("Names"), "Catalog /Names", issues);
  const root = names?.fields.get("EmbeddedFiles");
  if (root != null && root !== "null") await visitNameTree(index, root, 0);
  readAssociatedFiles(index, catalog.fields.get("AF"));
  if (index.truncated) {
    issues.push("Embedded file inspection limit reached.");
  }
  return inspectReferences(index, encryption == null ? readPdfTextString : () => null);
};
