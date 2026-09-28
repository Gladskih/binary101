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
  assert.ok(result?.issues?.includes("WEVT event 1001 has an invalid template offset."));
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

void test("walks multiple event records and element descriptors", () => {
  // libfwevt: WEVT element descriptors are eight bytes; EVNT records are 48 bytes.
  const bytes = new Uint8Array(240);
  const view = new DataView(bytes.buffer);
  const write = (offset: number, name: string): void => {
    bytes.set(new TextEncoder().encode(name), offset);
  };
  write(0, "CRIM"); view.setUint32(4, 240, true); view.setUint32(12, 1, true);
  view.setUint32(32, 40, true);
  write(40, "WEVT"); view.setUint32(44, 200, true); view.setUint32(52, 2, true);
  view.setUint32(60, 80, true); view.setUint32(68, 192, true);
  write(80, "EVNT"); view.setUint32(84, 112, true); view.setUint32(88, 2, true);
  view.setUint16(96, 1001, true); view.setUint32(112, 41, true);
  view.setUint16(144, 1002, true); view.setUint32(160, 42, true);
  write(192, "LEVL"); view.setUint32(196, 24, true); view.setUint32(200, 1, true);
  view.setUint32(204, 5, true); view.setUint32(208, 43, true);
  const result = addWevtTemplatePreview(bytes, "WEVT_TEMPLATE");
  const provider = result?.preview?.wevtTemplate?.providers[0];
  assert.deepEqual(provider?.events.map(event => [event.id, event.messageId]),
    [[1001, 41], [1002, 42]]);
  assert.deepEqual(provider?.elements.map(element => [element.kind, element.offset]),
    [["EVNT", 80], ["LEVL", 192]]);
  assert.deepEqual(provider?.metadata, [{ kind: "LEVL", id: "5", name: null, messageId: 43 }]);
  assert.deepEqual(result?.issues, undefined);
});

void test("walks multiple provider descriptors", () => {
  const bytes = new Uint8Array(104);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("CRIM"));
  view.setUint32(4, 104, true); view.setUint32(12, 2, true);
  bytes[16] = 1; view.setUint32(32, 64, true);
  bytes[36] = 2; view.setUint32(52, 84, true);
  bytes.set(new TextEncoder().encode("WEVT"), 64);
  view.setUint32(68, 20, true); view.setUint32(72, 0xffffffff, true);
  bytes.set(new TextEncoder().encode("WEVT"), 84);
  view.setUint32(88, 20, true); view.setUint32(92, 99, true);
  const result = addWevtTemplatePreview(bytes, "WEVT_TEMPLATE");
  assert.deepEqual(result?.preview?.wevtTemplate?.providers.map(provider =>
    [provider.guid, provider.messageId]), [
    ["00000001-0000-0000-0000-000000000000", null],
    ["00000002-0000-0000-0000-000000000000", 99]
  ]);
  assert.equal(result?.issues, undefined);
});

void test("reports an EVNT header cut off at the manifest boundary", () => {
  const bytes = fixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(60, 128, true);
  bytes.set(new TextEncoder().encode("EVNT"), 128);
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues,
    ["WEVT EVNT table is invalid or truncated."]);
});

void test("checks CRIM size, provider count and version at their boundaries", () => {
  const bytes = fixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(4, 15, true);
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues,
    ["WEVT_TEMPLATE CRIM size is invalid."]);
  view.setUint32(4, bytes.length + 1, true);
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues,
    ["WEVT_TEMPLATE CRIM size is invalid."]);
  view.setUint32(4, bytes.length, true);
  view.setUint32(12, 7, true);
  const result = addWevtTemplatePreview(bytes, "WEVT_TEMPLATE");
  assert.equal(result?.issues?.[0], "WEVT_TEMPLATE provider directory is truncated.");
  assert.equal(result?.preview?.wevtTemplate?.providers.length, 1);
  assert.equal(result?.preview?.wevtTemplate?.version, "3.1");
});

void test("checks EVNT size and count at their boundaries", () => {
  const bytes = fixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(76, 15, true);
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues,
    ["WEVT EVNT table size is invalid."]);
  view.setUint32(76, 0xffffffff, true);
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues,
    ["WEVT EVNT table size is invalid."]);
  view.setUint32(76, 16, true);
  view.setUint32(80, 0, true);
  const result = addWevtTemplatePreview(bytes, "WEVT_TEMPLATE");
  assert.deepEqual(result?.preview?.wevtTemplate?.providers[0]?.events, []);
  assert.equal(result?.issues, undefined);
});

void test("checks WEVT size at its lower and upper boundaries", () => {
  const bytes = fixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(44, 20, true);
  view.setUint32(52, 0, true);
  assert.equal(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues, undefined);
  view.setUint32(44, 101, true);
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues,
    ["WEVT provider size is invalid."]);
});

void test("accepts the shortest CRIM and reports trailing bytes after it", () => {
  const bytes = new Uint8Array(20);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("CRIM"));
  view.setUint32(4, 16, true);
  assert.equal(addWevtTemplatePreview(bytes.subarray(0, 16), "WEVT_TEMPLATE")?.issues,
    undefined);
  bytes[16] = 1;
  assert.deepEqual(addWevtTemplatePreview(bytes, "WEVT_TEMPLATE")?.issues,
    ["WEVT_TEMPLATE has nonzero trailing bytes outside CRIM."]);
});

void test("keeps provider descriptors outside a 16-byte CRIM excluded", () => {
  const bytes = fixture();
  new DataView(bytes.buffer).setUint32(4, 16, true);
  const result = addWevtTemplatePreview(bytes, "WEVT_TEMPLATE");
  assert.deepEqual(result?.preview?.wevtTemplate?.providers, []);
  assert.ok(result?.issues?.includes("WEVT_TEMPLATE provider directory is truncated."));
});

void test("limits EVNT records to the declared table size", () => {
  const bytes = new Uint8Array(160);
  bytes.set(fixture());
  const view = new DataView(bytes.buffer);
  view.setUint32(4, bytes.length, true);
  view.setUint32(76, 80, true); view.setUint32(80, 2, true);
  const result = addWevtTemplatePreview(bytes, "WEVT_TEMPLATE");
  assert.equal(result?.preview?.wevtTemplate?.providers[0]?.events.length, 1);
  assert.deepEqual(result?.issues, ["WEVT event definitions are truncated."]);
});

void test("accepts a valid event template offset without a warning", () => {
  const bytes = fixture();
  new DataView(bytes.buffer).setUint32(108, 72, true);
  const result = addWevtTemplatePreview(bytes, "WEVT_TEMPLATE");
  assert.equal(result?.preview?.wevtTemplate?.providers[0]?.events[0]?.templateOffset, 72);
  assert.equal(result?.issues, undefined);
});

const structuredSectionsFixture = (): Uint8Array => {
  // WEVT element descriptors are eight bytes; section headers are twelve bytes.
  const kinds = ["CHAN", "KEYW", "LEVL", "OPCO", "TASK"];
  const lengths = [16, 16, 12, 12, 28];
  const bytes = new Uint8Array(304);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("CRIM"));
  view.setUint32(4, bytes.length, true); view.setUint32(12, 1, true);
  view.setUint32(32, 40, true);
  bytes.set(new TextEncoder().encode("WEVT"), 40);
  view.setUint32(44, 68, true); view.setUint32(52, 6, true);
  let cursor = 108;
  for (const [index, kind] of kinds.entries()) {
    view.setUint32(60 + index * 8, cursor, true);
    bytes.set(new TextEncoder().encode(kind), cursor);
    view.setUint32(cursor + 4, 12 + (lengths[index] ?? 0), true);
    view.setUint32(cursor + 8, 1, true);
    view.setUint32(cursor + 12, index + 1, true);
    cursor += 12 + (lengths[index] ?? 0);
  }
  view.setUint32(100, cursor, true);
  bytes.set(new TextEncoder().encode("TTBL"), cursor);
  view.setUint32(cursor + 4, 52, true); view.setUint32(cursor + 8, 1, true);
  bytes.set(new TextEncoder().encode("TEMP"), cursor + 12);
  view.setUint32(cursor + 16, 40, true);
  return bytes;
};

void test("dispatches every structured provider section", () => {
  const result = addWevtTemplatePreview(structuredSectionsFixture(), "WEVT_TEMPLATE");
  const provider = result?.preview?.wevtTemplate?.providers[0];
  assert.deepEqual(provider?.metadata.map(item => item.kind),
    ["CHAN", "KEYW", "LEVL", "OPCO", "TASK"]);
  assert.equal(provider?.templates.length, 1);
  assert.equal(result?.issues, undefined);
});

void test("reports a malformed MAPS section through the provider directory", () => {
  const bytes = fixture();
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("MAPS"), 72);
  view.setUint32(76, 11, true);
  const result = addWevtTemplatePreview(bytes, "WEVT_TEMPLATE");
  assert.deepEqual(result?.issues, ["WEVT MAPS section size is invalid."]);
  assert.deepEqual(result?.preview?.wevtTemplate?.providers[0]?.elements,
    [{ kind: "MAPS", offset: 72 }]);
});
