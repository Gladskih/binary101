import type { ResourceLangWithPreview, ResourceMenuItemPreview, ResourceXmlTreeNode } from "./preview/types.js";
import { readMfcDocumentTemplate } from "./preview/mfc-document-template.js";

export interface ResourceCommandReference {
  relation: string;
  types: string[];
  key: number;
  targetKind: "resource" | "string";
}

export const resourceNumericId = (value: string | undefined | null): number | null => {
  if (!value || !/^\d+$/u.test(value)) return null;
  const number = Number(value);
  return Number.isSafeInteger(number) && number <= 0xffffffff ? number : null;
};

const menuCommands = (items: ResourceMenuItemPreview[]): number[] => {
  const ids: number[] = [];
  const stack = [...items];
  while (stack.length) {
    const item = stack.pop()!;
    if (item.id !== null) ids.push(item.id);
    for (const child of item.children) stack.push(child);
  }
  return ids;
};

const xmlCommands = (root: ResourceXmlTreeNode): number[] => {
  const ids: number[] = [];
  const nodes = [root];
  while (nodes.length) {
    const node = nodes.pop()!;
    if (node.name === "ELEMENT" || node.name === "BUTTON_MAIN") {
      const value = node.children.find(child => child.name === "ID")?.children
        .find(child => child.name === "VALUE")?.text;
      const id = resourceNumericId(value);
      if (id !== null) ids.push(id);
    }
    for (const child of node.children) nodes.push(child);
  }
  return ids;
};

const documentTemplates = (leaf: ResourceLangWithPreview): ResourceCommandReference[] =>
  (leaf.stringTable ?? []).flatMap(entry => entry.id === null || !readMfcDocumentTemplate(entry.text) ? [] :
    ["MENU", "GROUP_ICON", "ACCELERATOR"].map(type => ({
      relation: `Possible MFC document template #${entry.id}`, types: [type], key: entry.id!,
      targetKind: "resource" as const })));

const directCommands = (leaf: ResourceLangWithPreview): number[] => [
  ...(leaf.toolbar?.items ?? []), ...(leaf.acceleratorPreview?.entries.map(entry => entry.id) ?? []),
  ...(leaf.ribbonBml?.commands.map(command => command.id) ?? []), ...menuCommands(leaf.menuPreview?.items ?? [])];

export const collectResourceCommandReferences = (leaf: ResourceLangWithPreview): ResourceCommandReference[] => {
  const commands = new Set(directCommands(leaf));
  if (leaf.previewKind === "ribbonXml" && leaf.xmlTree) {
    for (const id of xmlCommands(leaf.xmlTree)) commands.add(id);
  }
  const references: ResourceCommandReference[] = [...commands].filter(id => id > 0).map(id =>
    ({ relation: `Command #${id} string`, types: ["STRING"], key: id, targetKind: "string" }));
  return [...references, ...documentTemplates(leaf)];
};
