import assert from "node:assert/strict";
import { test } from "node:test";
import { linkWevtMessages } from "../../../../../../analyzers/pe/resources/preview/wevt-message-links.js";
import type { ResourceDetailGroup } from "../../../../../../analyzers/pe/resources/preview/types.js";

const fixture = (): ResourceDetailGroup[] => [
  { typeName: "MESSAGETABLE", entries: [{ id: 1, name: null, langs: [
    { lang: 1033, messageTable: { messages: [{ id: 42, strings: ["Hello"] }], truncated: false } },
    { lang: 1031, messageTable: { messages: [{ id: 42, strings: ["Hallo"] }], truncated: false } }
  ] }] },
  { typeName: "WEVT_TEMPLATE", entries: [{ id: 1, name: null, langs: [
    { lang: 1033, wevtTemplate: { version: "3.1", providers: [
      { guid: "test", messageId: null, elements: [], metadata: [], templates: [], events: [
        { id: 1, version: 0, channel: 0, level: 0, opcode: 0, task: 0,
          keywords: "0x0", messageId: 42, templateOffset: null }
      ] }
    ] } },
    { lang: 1041, wevtTemplate: { version: "3.1", providers: [
      { guid: "test", messageId: null, elements: [], metadata: [], templates: [], events: [
        { id: 1, version: 0, channel: 0, level: 0, opcode: 0, task: 0,
          keywords: "0x0", messageId: 42, templateOffset: null }
      ] }
    ] } }
  ] }] }
] as ResourceDetailGroup[];

void test("links only same-language MESSAGETABLE strings", () => {
  const result = linkWevtMessages(fixture());
  assert.equal(result[1]?.entries[0]?.langs[0]?.wevtTemplate?.providers[0]?.events[0]?.messageText,
    "Hello");
  assert.equal(result[1]?.entries[0]?.langs[1]?.wevtTemplate?.providers[0]?.events[0]?.messageText,
    undefined);
});

void test("returns resources without message tables unchanged", () => {
  const detail = fixture().slice(1);
  assert.strictEqual(linkWevtMessages(detail), detail);
});

void test("uses neutral messages and preserves the first text for duplicate IDs", () => {
  const detail = fixture();
  const table = detail[0]?.entries[0]?.langs[0];
  const event = detail[1]?.entries[0]?.langs[0]?.wevtTemplate?.providers[0]?.events[0];
  assert.ok(table?.messageTable && event);
  table.lang = null;
  table.messageTable.messages.push({ id: 42, strings: ["Duplicate"] });
  const template = detail[1]?.entries[0]?.langs[0];
  assert.ok(template);
  template.lang = null;
  const linked = linkWevtMessages(detail);
  assert.equal(linked[1]?.entries[0]?.langs[0]?.wevtTemplate?.providers[0]?.events[0]?.messageText,
    "Hello");
});

void test("keeps undecoded WEVT leaves and events without message IDs", () => {
  const detail = fixture();
  const langs = detail[1]?.entries[0]?.langs;
  assert.ok(langs);
  langs.push({ lang: 1033 } as typeof langs[number]);
  const event = langs[0]?.wevtTemplate?.providers[0]?.events[0];
  assert.ok(event);
  event.messageId = null;
  const linked = linkWevtMessages(detail);
  assert.equal(linked[1]?.entries[0]?.langs[0]?.wevtTemplate?.providers[0]?.events[0]?.messageText,
    undefined);
  assert.equal(linked[1]?.entries[0]?.langs[2]?.wevtTemplate, undefined);
});

void test("joins multiple message strings and leaves other resource groups intact", () => {
  const detail = fixture();
  const message = detail[0]?.entries[0]?.langs[0]?.messageTable?.messages[0];
  assert.ok(message);
  message.strings.push("World");
  const linked = linkWevtMessages(detail);
  assert.strictEqual(linked[0], detail[0]);
  assert.equal(linked[1]?.entries[0]?.langs[0]?.wevtTemplate?.providers[0]?.events[0]
    ?.messageText, "Hello | World");
});

void test("links provider and metadata message IDs in the matching language", () => {
  const detail = fixture();
  const table = detail[0]?.entries[0]?.langs[0]?.messageTable;
  const provider = detail[1]?.entries[0]?.langs[0]?.wevtTemplate?.providers[0];
  assert.ok(table && provider);
  table.messages.push({ id: 43, strings: ["Provider name"] });
  table.messages.push({ id: 44, strings: ["Level name"] });
  table.messages.push({ id: 45, strings: ["Map value"] });
  provider.messageId = 43;
  provider.metadata.push({ kind: "LEVL", id: "4", name: "Level", messageId: 44 });
  provider.maps = [{ offset: 16, kind: "VMAP", name: "Map",
    entries: [{ value: 7, messageId: 45 }] }];
  const linked = linkWevtMessages(detail);
  const result = linked[1]?.entries[0]?.langs[0]?.wevtTemplate?.providers[0];
  assert.equal(result?.messageText, "Provider name");
  assert.equal(result?.metadata[0]?.messageText, "Level name");
  assert.equal(result?.maps?.[0]?.entries[0]?.messageText, "Map value");
});

void test("does not add messageText when an ID has no message", () => {
  const detail = fixture();
  const provider = detail[1]?.entries[0]?.langs[0]?.wevtTemplate?.providers[0];
  assert.ok(provider);
  provider.messageId = 999;
  const linked = linkWevtMessages(detail);
  const result = linked[1]?.entries[0]?.langs[0]?.wevtTemplate?.providers[0];
  assert.equal(Object.hasOwn(result ?? {}, "messageText"), false);
});
