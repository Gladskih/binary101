import type { ResourceDetailGroup, ResourceLangWithPreview } from "./preview/types.js";

export interface ResourceLocation { group: number; entry: number; language: number }
export interface ResourceCatalog {
  detail: ResourceDetailGroup[];
  byKey: Map<string, ResourceLocation[]>;
  byContent: Map<string, ResourceLocation[]>;
}
export interface ResourceResolution {
  kind: "exact" | "neutral" | "candidate" | "ambiguous" | "missing";
  targets: ResourceLocation[];
}

const key = (type: string, name: number | string): string => JSON.stringify([type, name]);

export const indexResourceLeaves = (detail: ResourceDetailGroup[]): ResourceCatalog => {
  const byKey = new Map<string, ResourceLocation[]>();
  const byContent = new Map<string, ResourceLocation[]>();
  detail.forEach((group, groupIndex) => group.entries.forEach((entry, entryIndex) => {
    const name = entry.name ?? entry.id;
    if (name === null) return;
    const locations = byKey.get(key(group.typeName, name)) ?? [];
    entry.langs.forEach((leaf, language) => {
      const location = { group: groupIndex, entry: entryIndex, language };
      locations.push(location);
      for (const item of [...(leaf.stringTable ?? []), ...(leaf.messageTable?.messages ?? [])]) {
        if (item.id === null) continue;
        const contentKey = key(group.typeName, item.id);
        const contents = byContent.get(contentKey) ?? [];
        contents.push(location); byContent.set(contentKey, contents);
      }
    });
    byKey.set(key(group.typeName, name), locations);
  }));
  return { detail, byKey, byContent };
};

export const resourceAt = (
  catalog: ResourceCatalog, location: ResourceLocation
): ResourceLangWithPreview | undefined =>
  catalog.detail[location.group]?.entries[location.entry]?.langs[location.language];

const resolveLanguage = (
  catalog: ResourceCatalog, targets: ResourceLocation[], language: number | null
): ResourceResolution => {
  const exact = targets.filter(target => resourceAt(catalog, target)?.lang === language);
  if (exact.length) return { kind: exact.length === 1 ? "exact" : "ambiguous", targets: exact };
  const neutral = targets.filter(target => {
    const lang = resourceAt(catalog, target)?.lang;
    return lang === 0 || lang === null;
  });
  if (neutral.length) return { kind: neutral.length === 1 ? "neutral" : "ambiguous", targets: neutral };
  // User/thread UI languages and external MUI modules are unavailable to static analysis.
  // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-findresourceexw
  return { kind: targets.length ? "candidate" : "missing", targets };
};

export const resolveResourceReference = (
  catalog: ResourceCatalog, type: string, name: number | string, language: number | null
): ResourceResolution => resolveLanguage(catalog, catalog.byKey.get(key(type, name)) ?? [], language);

export const resolveResourceContent = (
  catalog: ResourceCatalog, type: "STRING" | "MESSAGETABLE", id: number, language: number | null
): ResourceResolution => resolveLanguage(catalog, catalog.byContent.get(key(type, id)) ?? [], language);

export const resolveResourceAlternatives = (catalog: ResourceCatalog, types: string[],
  name: number | string, language: number | null): ResourceResolution => {
  const resolutions = types.map(type => resolveResourceReference(catalog,type,name,language));
  const present = resolutions.filter(item => item.kind !== "missing");
  const confirmed = present.filter(item => item.kind !== "candidate");
  if (confirmed.length === 1) return confirmed[0]!;
  if (confirmed.length > 1) return {kind:"ambiguous",targets:confirmed.flatMap(item=>item.targets)};
  return {kind:present.length ? "candidate" : "missing",targets:present.flatMap(item=>item.targets)};
};
