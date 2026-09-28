"use strict";

import type {
  ResourceDetailGroup, ResourceLangWithPreview, ResourceWevtProvider
} from "./types.js";

const indexMessages = (detail: ResourceDetailGroup[]): Map<number, Map<number, string>> => {
  const messages = new Map<number, Map<number, string>>();
  for (const group of detail.filter(entry => entry.typeName === "MESSAGETABLE")) {
    for (const entry of group.entries) {
      for (const lang of entry.langs) {
        const byId = messages.get(lang.lang ?? 0) ?? new Map<number, string>();
        for (const message of lang.messageTable?.messages ?? []) {
          if (!byId.has(message.id)) byId.set(message.id, message.strings.join(" | "));
        }
        messages.set(lang.lang ?? 0, byId);
      }
    }
  }
  return messages;
};

const linkMessage = <Value extends { messageId: number | null }>(
  value: Value, messages: Map<number, string>
): Value => {
  const messageText = value.messageId === null ? undefined : messages.get(value.messageId);
  return { ...value, ...(messageText !== undefined ? { messageText } : {}) };
};

const linkProvider = (
  provider: ResourceWevtProvider, messages: Map<number, string>
): ResourceWevtProvider => ({
  ...linkMessage(provider, messages),
  metadata: provider.metadata.map(entry => linkMessage(entry, messages)),
  events: provider.events.map(event => linkMessage(event, messages)),
  ...(provider.maps ? { maps: provider.maps.map(map => ({ ...map,
    entries: map.entries.map(entry => linkMessage(entry, messages)) })) } : {})
});

const linkLanguage = (
  lang: ResourceLangWithPreview, messages: Map<number, Map<number, string>>
): ResourceLangWithPreview => {
  if (!lang.wevtTemplate) return lang;
  const byId = messages.get(lang.lang ?? 0) ?? messages.get(0);
  if (!byId?.size) return lang;
  return { ...lang, wevtTemplate: { ...lang.wevtTemplate,
    providers: lang.wevtTemplate.providers.map(provider => linkProvider(provider, byId)) } };
};

export const linkWevtMessages = (detail: ResourceDetailGroup[]): ResourceDetailGroup[] => {
  const messages = indexMessages(detail);
  if (!messages.size) return detail;
  return detail.map(group => group.typeName === "WEVT_TEMPLATE"
    ? { ...group, entries: group.entries.map(entry => ({ ...entry,
      langs: entry.langs.map(lang => linkLanguage(lang, messages)) })) }
    : group);
};
