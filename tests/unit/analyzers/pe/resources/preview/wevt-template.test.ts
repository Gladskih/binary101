import assert from "node:assert/strict";
import { test } from "node:test";
import { addWevtTemplatePreview } from "../../../../../../analyzers/pe/resources/preview/wevt-template.js";
import { renderPreviewCell, renderPreviewSummary } from "../../../../../../renderers/pe/resource-preview-cell.js";
import { createPreviewLangEntry } from "../../../../../helpers/pe-resource-preview-fixture.js";

const fixture = (): Uint8Array => {
  // libfwevt Windows Event manifest binary format: CRIM, WEVT, EVNT, 48-byte event.
  // https://github.com/libyal/libfwevt/blob/main/documentation/Windows%20Event%20manifest%20binary%20format.asciidoc
  const bytes = new Uint8Array(140);
  const view = new DataView(bytes.buffer);
  const write = (offset: number, value: string): void => {
    for (let index = 0; index < value.length; index += 1) bytes[offset + index] = value.charCodeAt(index);
  };
  write(0, "CRIM"); view.setUint32(4, bytes.length, true);
  view.setUint16(8, 3, true); view.setUint16(10, 1, true); view.setUint32(12, 1, true);
  bytes.set([1, 2, 3, 4], 16); view.setUint32(32, 40, true);
  write(40, "WEVT"); view.setUint32(44, 100, true);
  view.setUint32(48, 42, true); view.setUint32(52, 1, true);
  view.setUint32(60, 72, true);
  write(72, "EVNT"); view.setUint32(76, 68, true); view.setUint32(80, 1, true);
  view.setUint16(88, 1001, true); bytes[90] = 2; bytes[91] = 3;
  bytes[92] = 4; bytes[93] = 5; view.setUint16(94, 6, true);
  view.setBigUint64(96, 0x1234n, true); view.setUint32(104, 42, true);
  return bytes;
};

void test("reads provider GUID, event metadata and message identifiers", () => {
  const result = addWevtTemplatePreview(fixture(), "WEVT_TEMPLATE");
  assert.equal(result?.preview?.wevtTemplate?.providers[0]?.guid,
    "04030201-0000-0000-0000-000000000000");
  assert.deepEqual(result?.preview?.wevtTemplate?.providers[0]?.events[0], {
    id: 1001, version: 2, channel: 3, level: 4, opcode: 5, task: 6,
    keywords: "0x0000000000001234", messageId: 42, templateOffset: null
  });
  assert.equal(result?.issues, undefined);
  const lang = { ...createPreviewLangEntry(0, 0), ...result?.preview };
  assert.equal(renderPreviewSummary(lang), "1 event providers");
  assert.match(renderPreviewCell(lang), /1001/);
});

void test("bounds checks CRIM, provider and event descriptors", () => {
  const bytes = fixture();
  assert.equal(addWevtTemplatePreview(bytes.subarray(0, 15), "WEVT_TEMPLATE")?.issues?.length, 1);
  assert.ok(addWevtTemplatePreview(bytes.subarray(0, 30), "WEVT_TEMPLATE")?.issues?.length);
  assert.ok(addWevtTemplatePreview(bytes.subarray(0, 90), "WEVT_TEMPLATE")?.issues?.length);
  assert.equal(addWevtTemplatePreview(bytes, "RCDATA"), null);
  bytes[0] = 0;
  assert.match(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues?.[0] ?? "", /CRIM/);
  bytes[0] = "C".charCodeAt(0);
  new DataView(bytes.buffer).setUint32(32, 0xffffffff, true);
  assert.match(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues?.[0] ?? "", /provider/);
});

void test("reports invalid event count and template offset", () => {
  const bytes = fixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(80, 2, true);
  view.setUint32(108, 0xffffffff, true);
  const result = addWevtTemplatePreview(bytes, "WEVT_TEMPLATE");
  assert.equal(result?.preview?.wevtTemplate?.providers[0]?.events.length, 1);
  assert.ok(result?.issues?.some(issue => /event definitions are truncated/.test(issue)));
  assert.ok(result?.issues?.some(issue => /template offset/.test(issue)));
});

void test("accepts zero padding after CRIM and warns on nonzero trailing data", () => {
  const bytes = new Uint8Array(144);
  bytes.set(fixture());
  assert.equal(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues, undefined);
  bytes[143] = 1;
  assert.match(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues?.[0] ?? "",
    /nonzero trailing bytes/);
});

void test("rejects malformed WEVT headers and element offsets", () => {
  const bytes = fixture();
  const view = new DataView(bytes.buffer);
  bytes[40] = 0;
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues,
    ["WEVT provider offset or signature is invalid."]);
  bytes[40] = "W".charCodeAt(0);
  view.setUint32(44, 19, true);
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues,
    ["WEVT provider size is invalid."]);
  view.setUint32(44, 100, true);
  view.setUint32(60, 0xffffffff, true);
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues,
    ["WEVT provider element offset is invalid."]);
});

void test("checks EVNT size and decodes absent message IDs", () => {
  const bytes = fixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(76, 15, true);
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues,
    ["WEVT EVNT table size is invalid."]);
  view.setUint32(76, 68, true);
  view.setUint32(104, 0xffffffff, true);
  view.setUint32(108, 72, true);
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.preview
    ?.wevtTemplate?.providers[0]?.events[0], {
    id: 1001, version: 2, channel: 3, level: 4, opcode: 5, task: 6,
    keywords: "0x0000000000001234", messageId: null, templateOffset: 72
  });
});

void test("reports a truncated provider element directory", () => {
  const bytes = fixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(44, 28, true);
  view.setUint32(52, 2, true);
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues,
    ["WEVT provider element directory is truncated."]);
});
