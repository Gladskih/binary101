import { parsePagesDictionary } from "./dictionary.js";
import type { PdfObjectResolver } from "./object-resolver.js";
import { readPageGeometry, readUserUnit } from "./page-geometry.js";
import type { PdfPageGeometry } from "./page-geometry.js";
import { readArray, readName, readReference } from "./syntax.js";
import type { PdfDictionary } from "./syntax.js";
import type { PdfIndirectRef, PdfPage, PdfPages } from "./types.js";

interface PageNode {
  ref: PdfIndirectRef;
  parent: PdfIndirectRef | null;
  inherited: PdfPageGeometry;
  depth: number;
}

interface PageTree {
  resolve: PdfObjectResolver;
  issues: string[];
  visited: Set<number>;
  entries: PdfPage[];
  remaining: number;
  incomplete: boolean;
}

const warn = (tree: PageTree, message: string): void => {
  tree.incomplete = true;
  tree.issues.push(message);
};

const visitPage = (tree: PageTree, ref: PdfIndirectRef, object: PdfDictionary, geometry: PdfPageGeometry): void => {
  if (!geometry.mediaBox) tree.issues.push("Page " + ref.objectNumber + " has no resolved /MediaBox.");
  tree.entries.push({ ref, ...geometry, userUnit: readUserUnit(object.fields.get("UserUnit"), tree.issues) });
};

const checkParent = (tree: PageTree, node: PageNode, object: PdfDictionary): void => {
  if (!node.parent) return;
  const parent = readReference(object.fields.get("Parent"));
  if (parent?.objectNumber !== node.parent.objectNumber || parent.generation !== node.parent.generation) {
    tree.issues.push("Page-tree object " + node.ref.objectNumber + " has a mismatched /Parent.");
  }
};

const readChildren = async (
  tree: PageTree, node: PageNode, object: PdfDictionary, geometry: PdfPageGeometry
): Promise<void> => {
  const children = readArray(object.fields.get("Kids"));
  if (!children) return warn(tree, "Page-tree node " + node.ref.objectNumber + " lacks a valid /Kids array.");
  for (const token of children) {
    if (tree.remaining <= 0) {
      if (tree.remaining === 0) warn(tree, "Page tree node limit reached.");
      tree.remaining = -1;
      return;
    }
    const ref = readReference(token);
    tree.remaining -= 1;
    if (!ref) {
      warn(tree, "Page-tree /Kids contains an invalid indirect reference.");
      continue;
    }
    await visitNode(tree, { ref, parent: node.ref, inherited: geometry, depth: node.depth + 1 });
  }
};

const visitNode = async (tree: PageTree, node: PageNode, root?: PdfDictionary): Promise<void> => {
  if (tree.visited.has(node.ref.objectNumber)) {
    return warn(tree, "Repeated or cyclic page-tree object " + node.ref.objectNumber + ".");
  }
  if (node.depth >= 64) return warn(tree, "Page tree depth limit reached.");
  tree.visited.add(node.ref.objectNumber);
  const object = root ?? await tree.resolve.dictionary(node.ref, "Page tree");
  if (!object) {
    tree.incomplete = true;
    return;
  }
  checkParent(tree, node, object);
  const geometry = readPageGeometry(object.fields, node.inherited, tree.issues);
  switch (readName(object.fields.get("Type"))) {
    case "Pages": return readChildren(tree, node, object, geometry);
    case "Page": return visitPage(tree, node.ref, object, geometry);
    default: return warn(tree, "Page-tree child " + node.ref.objectNumber + " has an invalid /Type.");
  }
};

export const readPageTree = async (
  resolve: PdfObjectResolver, ref: PdfIndirectRef, root: PdfDictionary, issues: string[]
): Promise<PdfPages> => {
  const tree: PageTree = { resolve, issues, visited: new Set(), entries: [], remaining: 1023, incomplete: false };
  const declared = parsePagesDictionary(root);
  if (declared.count == null) issues.push("Page tree root lacks a valid /Count.");
  await visitNode(tree, {
    ref, depth: 0, parent: null, inherited: { mediaBox: null, cropBox: null, rotation: 0 }
  }, root);
  if (!tree.incomplete && declared.count != null && declared.count !== tree.entries.length) {
    issues.push("Page tree root /Count declares " + declared.count +
      " pages but traversal found " + tree.entries.length + ".");
  }
  return { ...declared, entries: tree.entries };
};
