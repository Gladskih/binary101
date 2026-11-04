import { indexResourceLeaves, resolveResourceReference, resourceAt } from "../resource-index.js";
import type { ResourceCatalog, ResourceLocation } from "../resource-index.js";
import type { ResourceDetailGroup, ResourceLangWithPreview } from "./types.js";
import type { ResourceImageGroup } from "./types.js";

type GroupImage = ResourceImageGroup["entries"][number];

const confirmedTarget = (catalog: ResourceCatalog, type: string, id: number, lang: number | null) => {
  const resolution = resolveResourceReference(catalog, type, id, lang);
  return resolution.kind === "exact" || resolution.kind === "neutral" ? resolution.targets[0]! : null;
};

const checkImage = (catalog: ResourceCatalog, leaf: ResourceLangWithPreview, image: GroupImage): string[] => {
  const type = leaf.imageGroup!.type;
  const resolution = resolveResourceReference(catalog, type, image.id, leaf.lang);
  if (resolution.kind === "missing") return [
    `GROUP_${type} references missing ${type} leaf ID ${image.id}.`];
  const location = confirmedTarget(catalog, type, image.id, leaf.lang);
  if (!location) return [];
  const target = resourceAt(catalog, location)!;
  const issues: string[] = [];
  if (!target.previewDataUrl && target.previewKind !== "deferred") {
    issues.push(`GROUP_${type} references ${type} leaf ID ${image.id}, but its image preview is unavailable.`);
    issues.push(...(target.previewIssues ?? []));
  }
  if (image.size !== target.size) issues.push(`GROUP_${type} entry #${image.id} size differs from its leaf.`);
  return issues;
};

const resolveGroup = (catalog: ResourceCatalog, leaf: ResourceLangWithPreview): ResourceLangWithPreview => {
  if (!leaf.imageGroup) return leaf;
  const issues = [...(leaf.previewIssues ?? []),
    ...leaf.imageGroup.entries.flatMap(image => checkImage(catalog, leaf, image))];
  return issues.length ? { ...leaf, previewIssues: issues } : leaf;
};

export const linkImageGroupPreviews = (detail: ResourceDetailGroup[]): ResourceDetailGroup[] => {
  const catalog = indexResourceLeaves(detail);
  return detail.map(group => group.typeName !== "GROUP_ICON" && group.typeName !== "GROUP_CURSOR"
    ? group : { ...group, entries: group.entries.map(entry => ({ ...entry,
      langs: entry.langs.map(leaf => resolveGroup(catalog, leaf)) })) });
};

const imageRank = (type: string, image: GroupImage): number[] => [
  Number(type === "CURSOR" && image.width === 32), image.width * image.height, image.bitCount];

const preferredImage = (type: string, previous: GroupImage, candidate: GroupImage): boolean => {
  const before = imageRank(type, previous);
  const after = imageRank(type, candidate);
  for (let index = 0; index < before.length; index += 1) {
    if (before[index] !== after[index]) return after[index]! > before[index]!;
  }
  return false;
};

export const resolveImageGroupTarget = (
  catalog: ResourceCatalog, leaf: ResourceLangWithPreview
): ResourceLocation | null => {
  const group = leaf.imageGroup;
  if (!group) return null;
  let selected: GroupImage | undefined;
  let location: ResourceLocation | null = null;
  for (const image of group.entries) {
    const candidate = confirmedTarget(catalog, group.type, image.id, leaf.lang);
    if (!candidate || !resourceAt(catalog, candidate)?.previewDataUrl) continue;
    if (selected && !preferredImage(group.type, selected, image)) continue;
    selected = image; location = candidate;
  }
  return location;
};
