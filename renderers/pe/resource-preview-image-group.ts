import type { ResourceImageGroup, ResourceLangWithPreview } from "../../analyzers/pe/resources/preview/types.js";
import { resolveResourceReference, resourceAt } from "../../analyzers/pe/resources/resource-index.js";
import { escapeHtmlText } from "../../html-utils.js";
import { resourceNavigationLink } from "./resource-preview-context.js";
import type { ResourcePreviewContext } from "./resource-preview-context.js";

const imagePreview = (leaf: ResourceLangWithPreview | undefined, kind: string, type: string, id: number): string => {
  const image = leaf?.previewDataUrl ? `<img class="peResourceImagePreview" src="${leaf.previewDataUrl}" alt="${type} #${id}" />` : escapeHtmlText(kind === "missing" ? "Not present in this file" : kind);
  return image + (leaf?.previewFields?.map(field => `<div>${escapeHtmlText(field.label)}: ${escapeHtmlText(field.value)}</div>`).join("") ?? "");
};

export const renderImageGroupPreview = (
  group: ResourceImageGroup, context: ResourcePreviewContext
): string => {
  const lang = resourceAt(context.catalog, context.source)?.lang ?? null;
  const rows = group.entries.map(image => {
    const resolution = resolveResourceReference(context.catalog, group.type, image.id, lang);
    const target = resolution.targets[0];
    const leaf = target && (resolution.kind === "exact" || resolution.kind === "neutral")
      ? resourceAt(context.catalog, target) : undefined;
    return `<tr><td>${target ? resourceNavigationLink(context.catalog, target) : `#${image.id}`}</td>` +
      `<td class="peNumeric">${image.width}×${image.height}</td>` +
      `<td class="peNumeric">${image.bitCount}</td><td class="peNumeric">${image.size}</td>` +
      `<td>${imagePreview(leaf, resolution.kind, group.type, image.id)}</td></tr>`;
  });
  return `<table class="table"><thead><tr><th>Image</th><th>Stored dimensions</th>` +
    `<th>Bits/pixel</th><th>Bytes</th><th>Preview</th></tr></thead>` +
    `<tbody>${rows.join("")}</tbody></table>`;
};
