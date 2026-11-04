import type { ResourceCatalog, ResourceLocation } from "../../analyzers/pe/resources/resource-index.js";
import { resolveResourceAlternatives, resourceAt } from "../../analyzers/pe/resources/resource-index.js";
import type { ResourceLink } from "../../analyzers/pe/resources/resource-links.js";
import { resolveImageGroupTarget } from "../../analyzers/pe/resources/preview/image-group-links.js";
import { escapeHtmlText } from "../../html-utils.js";
import type { PeResources } from "../../analyzers/pe/resources/index.js";
import { indexResourceLeaves } from "../../analyzers/pe/resources/resource-index.js";
import { collectResourceLinks } from "../../analyzers/pe/resources/resource-links.js";

export interface ResourcePreviewContext {
  catalog: ResourceCatalog;
  links: ResourceLink[];
  source: ResourceLocation;
  outgoing?: Map<string, ResourceLink[]>;
  incoming?: Map<string, ResourceLink[]>;
}

const previewModels = new WeakMap<PeResources, Omit<ResourcePreviewContext, "source">>();

export const getResourcePreviewModel = (resources: PeResources): Omit<ResourcePreviewContext, "source"> => {
  const cached = previewModels.get(resources);
  if (cached) return cached;
  const links = resources.links ?? collectResourceLinks(resources.detail);
  const outgoing = new Map<string, ResourceLink[]>();
  const incoming = new Map<string, ResourceLink[]>();
  for (const link of links) {
    const source = resourceAnchor(link.source);
    const references = outgoing.get(source) ?? [];
    references.push(link); outgoing.set(source, references);
    for (const target of link.resolution.targets) {
      const name = resourceAnchor(target);
      const users = incoming.get(name) ?? [];
      users.push(link); incoming.set(name, users);
    }
  }
  const model = { catalog: indexResourceLeaves(resources.detail), links, outgoing, incoming };
  previewModels.set(resources, model);
  return model;
};

export const resourceAnchor = (location: ResourceLocation): string =>
  `pe-resource-${location.group}-${location.entry}-${location.language}`;

export const resourceLocationLabel = (catalog: ResourceCatalog, location: ResourceLocation): string => {
  const group = catalog.detail[location.group];
  const entry = group?.entries[location.entry];
  if (!group || !entry) return "Resource (unavailable)";
  return `${group.typeName} ${entry.name ?? `#${entry.id ?? "?"}`} / ` +
    `LANG ${entry.langs[location.language]?.lang ?? "neutral"}`;
};

export const resourceNavigationLink = (catalog: ResourceCatalog, target: ResourceLocation): string =>
  `<a href="#${resourceAnchor(target)}" data-pe-resource-target="` +
  `${target.group}-${target.entry}-${target.language}">` +
  `${escapeHtmlText(resourceLocationLabel(catalog, target))}</a>`;

export const resolvedPreview = (
  context: ResourcePreviewContext | undefined, types: string[], key: number | string
) => {
  if (!context) return undefined;
  const language = resourceAt(context.catalog, context.source)?.lang ?? null;
  const resolution = resolveResourceAlternatives(context.catalog,types,key,language);
  if (resolution.kind === "exact" || resolution.kind === "neutral") {
    return resourceAt(context.catalog,resolution.targets[0]!);
  }
  return undefined;
};

export const resolvedResourceImage = (
  context: ResourcePreviewContext | undefined, types: string[], key: number | string
): string | undefined => {
  const preview = resolvedPreview(context, types, key);
  if (preview?.previewDataUrl) return preview.previewDataUrl;
  if (!context || !preview?.imageGroup) return undefined;
  const target = resolveImageGroupTarget(context.catalog, preview);
  return target ? resourceAt(context.catalog, target)?.previewDataUrl : undefined;
};

const sameLocation = (left: ResourceLocation, right: ResourceLocation): boolean =>
  left.group === right.group && left.entry === right.entry && left.language === right.language;

export const renderResourceConnections = (context: ResourcePreviewContext): string => {
  const outgoing = context.outgoing ? context.outgoing.get(resourceAnchor(context.source)) ?? [] :
    context.links.filter(link => sameLocation(link.source, context.source));
  const incoming = context.incoming ? context.incoming.get(resourceAnchor(context.source)) ?? [] :
    context.links.filter(link => link.resolution.targets.some(target => sameLocation(target, context.source)));
  if (!outgoing.length && !incoming.length) return "";
  const rows = outgoing.map(link => `<tr><td>${escapeHtmlText(link.relation)}</td><td>` +
    `${link.resolution.targets.map(target => resourceNavigationLink(context.catalog, target)).join(", ") ||
      escapeHtmlText(`${link.types.join(" / ")} ${typeof link.key === "number" ? "#" : ""}${link.key}`)}` +
    `</td><td>${link.evidence === "convention" ? "Convention; " : ""}` +
    `${link.resolution.kind === "missing" ? "Not present in this file" : link.resolution.kind}</td></tr>`);
  rows.push(...incoming.map(link => `<tr><td>Used by: ${escapeHtmlText(link.relation)}</td>` +
    `<td>${resourceNavigationLink(context.catalog, link.source)}</td>` +
    `<td>${escapeHtmlText(link.resolution.kind)}</td></tr>`));
  return `<details class="peResourceConnections"><summary>Resource references</summary>` +
    `<table class="table"><thead><tr><th>Relation</th><th>Resource</th><th>Resolution</th>` +
    `</tr></thead><tbody>${rows.join("")}</tbody></table></details>`;
};
