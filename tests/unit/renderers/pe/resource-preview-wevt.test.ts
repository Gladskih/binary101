import assert from "node:assert/strict";
import { test } from "node:test";
import { renderWevtTemplatePreview } from "../../../../renderers/pe/resource-preview-wevt.js";

void test("renders metadata, template fields and linked messages as escaped text", () => {
  const html = renderWevtTemplatePreview({ version: "3.1", providers: [{
    guid: "test-guid", messageId: 12, messageText: "<Provider>",
    elements: [{ kind: "EVNT", offset: 16 }],
    metadata: [{ kind: "LEVL", id: "4", name: "<Error>", messageId: 25,
      messageText: "<Level>" }],
    maps: [{ offset: 96, kind: "VMAP", name: "<Map>",
      entries: [{ value: 7, messageId: 45, messageText: "<Map value>" }] }],
    templates: [{ offset: 48, guid: "template-guid", xmlTree: {
      name: "<Event>", attributes: [], text: "{sub:0}", children: []
    }, fields: [
      { name: "<Payload>", inputType: 7, outputType: 8, count: 1, length: 4 }
    ] }],
    events: [{ id: 1001, version: 1, channel: 2, level: 4, opcode: 0,
      task: 3, keywords: "0x0001", messageId: 42, messageText: "<Hello>",
      templateOffset: 48 }]
  }] });
  assert.match(html, /Provider message ID/);
  assert.match(html, /&lt;Provider>/);
  assert.match(html, /&lt;Level>/);
  assert.match(html, /&lt;Map>/);
  assert.match(html, /&lt;Map value>/);
  assert.doesNotMatch(html, /<Provider>|<Level>/);
  assert.match(html, /&lt;Error>/);
  assert.match(html, /&lt;Payload> \(inType 7, outType 8, count 1, length 4\)/);
  assert.match(html, /&lt;Hello>/);
  assert.doesNotMatch(html, /<Hello>/);
  assert.match(html, /0x30/);
  assert.match(html, /0x30<br><span class="mono">template-guid<\/span>/);
  assert.match(html, /Fields: &lt;Payload>/);
  assert.match(html, /XML: &lt;&lt;Event>&gt;/);
  assert.match(html, /data-manifest-tree-viewer/);
});

void test("resolves an event against its matching TEMP offset", () => {
  const html = renderWevtTemplatePreview({ version: "3.1", providers: [{
    guid: "provider", messageId: null, elements: [], metadata: [],
    templates: [
      { offset: 40, guid: "first-guid", fields: [] },
      { offset: 80, guid: "second-guid", fields: [] }
    ],
    events: [{ id: 1, version: 0, channel: 0, level: 0, opcode: 0,
      task: 0, keywords: "0x0", messageId: null, templateOffset: 80 }]
  }] });
  assert.match(html, /0x50<br><span class="mono">second-guid<\/span>/);
  assert.doesNotMatch(html, /0x50<br><span class="mono">first-guid<\/span>/);
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
