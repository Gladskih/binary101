import { indexResourceLeaves, resolveResourceAlternatives, resolveResourceContent, resourceAt } from "./resource-index.js";
import type { ResourceCatalog, ResourceLocation, ResourceResolution } from "./resource-index.js";
import type { ResourceDetailGroup, ResourceLangWithPreview, ResourceXmlTreeNode } from "./preview/types.js";
import { resourceNumericId, collectResourceCommandReferences } from "./resource-command-references.js";

export interface ResourceLink {
  source: ResourceLocation;
  relation: string;
  types: string[];
  key: number | string;
  evidence: "explicit" | "convention";
  targetKind: "resource" | "string" | "message";
  resolution: ResourceResolution;
}

const link = (
  catalog: ResourceCatalog, source: ResourceLocation, relation: string,
  types: string[], key: number | string, evidence: ResourceLink["evidence"] = "explicit",
  targetKind: ResourceLink["targetKind"] = "resource"
): ResourceLink => {
  const language = resourceAt(catalog, source)?.lang ?? null;
  const resolution = targetKind === "resource" ? resolveResourceAlternatives(catalog, types, key, language) :
    resolveResourceContent(catalog, targetKind === "string" ? "STRING" : "MESSAGETABLE", Number(key), language);
  return { source, relation, types, key, evidence, targetKind, resolution };
};

const xmlImageKey = (node: ResourceXmlTreeNode): number | string | null => {
  const value = node.children.find(child => child.name === "VALUE")?.text;
  return value ? resourceNumericId(value) : node.children.find(child => child.name === "NAME")?.text ?? null;
};

const xmlImageLinks = (
  catalog: ResourceCatalog, source: ResourceLocation, root: ResourceXmlTreeNode
): ResourceLink[] => {
  const links: ResourceLink[] = [];
  const stack = [root];
  while (stack.length) {
    const node = stack.pop()!;
    if (["IMAGE", "IMAGE_SMALL", "IMAGE_LARGE"].includes(node.name)) {
      for (const id of node.children.filter(child => child.name === "ID" || child.name === "ID_HDPI")) {
        const key = xmlImageKey(id);
        if (key != null && key !== 0) links.push(link(catalog, source,
          `Ribbon ${node.name}${id.name === "ID_HDPI" ? " (high DPI)" : ""}`, ["BITMAP", "PNG"], key));
      }
    }
    for (const child of node.children) stack.push(child);
  }
  return links;
};

const dialogLinks = (
  catalog: ResourceCatalog, source: ResourceLocation, leaf: ResourceLangWithPreview
): ResourceLink[] => {
  if (!leaf.dialogPreview) return [];
  const dialog = leaf.dialogPreview;
  const links = dialog.menu !== null
    ? [link(catalog, source, "Dialog menu", ["MENU"], dialog.menu)] : [];
  for (const control of dialog.controls) {
    if (control.kind.toUpperCase() !== "STATIC" || control.title === null) continue;
    const style = control.style & 0x1f; // SS_TYPEMASK; WinUser.h Static Control Styles.
    if (style === 3 || style === 14) links.push(link(catalog, source,
      `Control #${control.id} image`, style === 3 ? ["GROUP_ICON"] : ["BITMAP"],
      control.title));
  }
  return links;
};

const imageAndFontLinks = (catalog: ResourceCatalog, source: ResourceLocation,
  leaf: ResourceLangWithPreview): ResourceLink[] => {
  const links: ResourceLink[] = [];
  for (const image of leaf.imageGroup?.entries ?? []) {
    links.push(link(catalog, source, "Group image", [leaf.imageGroup!.type], image.id));
  }
  for (const font of leaf.fontDirectory?.entries ?? []) {
    links.push(link(catalog, source, "Font directory entry", ["FONT"], font.ordinal));
  }
  return links;
};

const compiledRibbonLinks = (catalog: ResourceCatalog, source: ResourceLocation,
  leaf: ResourceLangWithPreview): ResourceLink[] => {
  const links: ResourceLink[] = [];
  for (const command of leaf.ribbonBml?.commands ?? []) {
    for (const resource of command.resources) {
      const image = resource.kind.toLowerCase().includes("image");
      links.push(link(catalog, source, `Command #${command.id}: ${resource.kind}`,
        image ? ["BITMAP", "PNG"] : ["STRING"],
        resource.resourceId, "explicit", image ? "resource" : "string"));
    }
  }
  return links;
};

const eventMessageLinks = (catalog: ResourceCatalog, source: ResourceLocation,
  leaf: ResourceLangWithPreview): ResourceLink[] => {
  const links: ResourceLink[] = [];
  for (const provider of leaf.wevtTemplate?.providers ?? []) {
    const messages = [provider, ...provider.events, ...provider.metadata,
      ...(provider.maps?.flatMap(map => map.entries) ?? [])];
    for (const message of messages) {
      if (message.messageId !== null) links.push(link(catalog, source, "Event message",
        ["MESSAGETABLE"], message.messageId, "explicit", "message"));
    }
  }
  return links;
};

const matchingResourceLinks = (catalog: ResourceCatalog, source: ResourceLocation,
  leaf: ResourceLangWithPreview): ResourceLink[] => {
  const entry = catalog.detail[source.group]!.entries[source.entry]!;
  const links: ResourceLink[] = [];
  const name = entry.name ?? entry.id;
  if (name !== null && (leaf.dialogInit || leaf.dialogLayout)) {
    links.push(link(catalog, source, "Matching dialog", ["DIALOG"], name));
  }
  if (name !== null && leaf.toolbar) {
    links.push(link(catalog, source, "Toolbar image strip", ["BITMAP"], name, "convention"));
  }
  return links;
};

const leafLinks = (
  catalog: ResourceCatalog, source: ResourceLocation
): ResourceLink[] => {
  const group = catalog.detail[source.group]!;
  const entry = group.entries[source.entry]!;
  const leaf = entry.langs[source.language]!;
  const links = dialogLinks(catalog, source, leaf);
  for (const reference of collectResourceCommandReferences(leaf)) {
    const association = link(catalog, source, reference.relation, reference.types,
      reference.key, "convention", reference.targetKind);
    if (association.resolution.kind !== "missing") links.push(association);
  }
  links.push(...matchingResourceLinks(catalog, source, leaf));
  links.push(...imageAndFontLinks(catalog, source, leaf),
    ...compiledRibbonLinks(catalog, source, leaf), ...eventMessageLinks(catalog, source, leaf));
  if (group.typeName === "RIBBON_XML" && leaf.xmlTree) {
    links.push(...xmlImageLinks(catalog, source, leaf.xmlTree));
  }

  return links;
};

export const collectResourceLinks = (detail: ResourceDetailGroup[]): ResourceLink[] => {
  const catalog = indexResourceLeaves(detail);
  return detail.flatMap((group, groupIndex) => group.entries.flatMap((entry, entryIndex) =>
    entry.langs.flatMap((_leaf, language) => {
      const links = leafLinks(catalog, { group: groupIndex, entry: entryIndex, language });
      return [...new Map(links.map(link => [JSON.stringify([link.relation, link.types, link.key,
        link.evidence, link.targetKind]), link])).values()];
    })));
};
