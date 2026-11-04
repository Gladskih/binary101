"use strict";

import { indexResourceLeaves, resolveResourceContent, resourceAt } from "../resource-index.js";
import type { ResourceCatalog } from "../resource-index.js";
import type {
  ResourceDetailGroup, ResourceLangWithPreview, ResourceWevtProvider
} from "./types.js";

const messageText = (catalog: ResourceCatalog, language: number | null, id: number): string | undefined => {
  const resolution = resolveResourceContent(catalog, "MESSAGETABLE", id, language);
  if (resolution.kind !== "exact" && resolution.kind !== "neutral") return undefined;
  return resourceAt(catalog, resolution.targets[0]!)?.messageTable?.messages
    .find(message => message.id === id)?.strings.join(" | ");
};

const linkMessage = <Value extends { messageId: number | null }>(
  value: Value, messages: (id: number) => string | undefined
): Value => {
  const messageText = value.messageId === null ? undefined : messages(value.messageId);
  return { ...value, ...(messageText !== undefined ? { messageText } : {}) };
};

const linkProvider = (
  provider: ResourceWevtProvider, messages: (id: number) => string | undefined
): ResourceWevtProvider => ({
  ...linkMessage(provider, messages),
  metadata: provider.metadata.map(entry => linkMessage(entry, messages)),
  events: provider.events.map(event => linkMessage(event, messages)),
  ...(provider.maps ? { maps: provider.maps.map(map => ({ ...map,
    entries: map.entries.map(entry => linkMessage(entry, messages)) })) } : {})
});

const linkLanguage = (
  lang: ResourceLangWithPreview, catalog: ResourceCatalog
): ResourceLangWithPreview => {
  if (!lang.wevtTemplate) return lang;
  const byId = (id: number) => messageText(catalog, lang.lang, id);
  return { ...lang, wevtTemplate: { ...lang.wevtTemplate,
    providers: lang.wevtTemplate.providers.map(provider => linkProvider(provider, byId)) } };
};

export const linkWevtMessages = (detail: ResourceDetailGroup[]): ResourceDetailGroup[] => {
  const catalog = indexResourceLeaves(detail);
  if (!catalog.byContent.size) return detail;
  return detail.map(group => group.typeName === "WEVT_TEMPLATE"
    ? { ...group, entries: group.entries.map(entry => ({ ...entry,
      langs: entry.langs.map(lang => linkLanguage(lang, catalog)) })) }
    : group);
};
