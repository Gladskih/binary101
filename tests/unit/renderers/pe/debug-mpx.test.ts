import assert from "node:assert/strict";
import { test } from "node:test";
import { renderMpxDebug } from "../../../../renderers/pe/debug-mpx.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";

void test("MPX explains selected and absent flags and summarizes unnamed fields", () => {
  const out: string[] = [];
  renderMpxDebug({ ...createDebugViewEntry(15, 0, 128), mpx: {
    flags: 5, unknown1: 0, unknown2: 42, unknown3: 0 } }, out);
  const html = out.join("");
  assert.match(html, /opt sel[^>]*[^]*>MPX enabled/);
  assert.match(html, /opt dim[^>]*[^]*>Driver runtime/);
  assert.match(html, /opt sel[^>]*[^]*>Fail fast/);
  assert.match(html, /3 unnamed fields; 1 nonzero/);
  assert.match(html, /application exception handler/);
  assert.match(html, /^<dl><dt/);
  assert.match(html, /MPX configuration/);
  assert.match(html, /Enable Intel Memory Protection Extensions/);
  assert.match(html, /Use driver runtime support; when clear, use a runtime DLL/);
  assert.match(html, /Uninterpreted data/);
  assert.match(html, /does not establish the meaning of these fields/);
  assert.doesNotMatch(html, /<table/);
});

void test("MPX retains unknown flags visibly and omits absent payloads", () => {
  const out: string[] = [];
  renderMpxDebug(createDebugViewEntry(15, 0, 0), out);
  assert.deepEqual(out, []);
  renderMpxDebug({ ...createDebugViewEntry(15, 0, 128), mpx: {
    flags: 0x80000000, unknown1: 0, unknown2: 0, unknown3: 0 } }, out);
  assert.match(out.join(""), /UNKNOWN_BITS_0x80000000/);
  assert.match(out.join(""), /3 unnamed fields; 0 nonzero/);
});
