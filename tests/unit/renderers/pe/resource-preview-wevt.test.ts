import assert from "node:assert/strict";
import { test } from "node:test";
import { renderWevtTemplatePreview } from "../../../../renderers/pe/resource-preview-wevt.js";

void test("renders metadata, template fields and linked messages as escaped text", () => {
  const html = renderWevtTemplatePreview({ version: "3.1", providers: [{
    guid: "test-guid", messageId: 12,
    elements: [{ kind: "EVNT", offset: 16 }],
    metadata: [{ kind: "LEVL", id: "4", name: "<Error>", messageId: 25 }],
    templates: [{ offset: 48, guid: "template-guid", fields: [
      { name: "<Payload>", inputType: 7, outputType: 8, count: 1, length: 4 }
    ] }],
    events: [{ id: 1001, version: 1, channel: 2, level: 4, opcode: 0,
      task: 3, keywords: "0x0001", messageId: 42, messageText: "<Hello>",
      templateOffset: 48 }]
  }] });
  assert.match(html, /Provider message ID/);
  assert.match(html, /&lt;Error>/);
  assert.match(html, /&lt;Payload> \(inType 7, outType 8, count 1, length 4\)/);
  assert.match(html, /&lt;Hello>/);
  assert.doesNotMatch(html, /<Hello>/);
  assert.match(html, /0x30/);
});

void test("renders absent names, message IDs and offsets without blank cells", () => {
  const html = renderWevtTemplatePreview({ version: "3.1", providers: [{
    guid: "test-guid", messageId: null,
    elements: [{ kind: "", offset: 16 }],
    metadata: [{ kind: "CHAN", id: "1", name: null, messageId: null }],
    templates: [{ offset: 48, guid: "template-guid", fields: [
      { name: null, inputType: 1, outputType: 1, count: 0, length: 0 }
    ] }],
    events: [{ id: 1, version: 0, channel: 0, level: 0, opcode: 0,
      task: 0, keywords: "0x0", messageId: null, templateOffset: null }]
  }] });
  assert.match(html, /Sections: unknown/);
  assert.match(html, /\(unnamed\)/);
  assert.match(html, /<td class="peNumeric">–<\/td>/);
  assert.doesNotMatch(html, /Provider message ID/);
});
