import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeReadyToRunDebugSections } from "../../../../../analyzers/pe/clr/ready-to-run-debug-sections.js";
import { createReadyToRunRendererFixture } from "../../../../helpers/ready-to-run-renderer-fixture.js";
import { debugSection } from "../../../../helpers/ready-to-run-debug-fixture.js";
import { MockFile } from "../../../../helpers/mock-file.js";

void test("decodes shared root/component debug sections once per image", async () => {
  const bytes = debugSection(new Uint8Array(), new Uint8Array());
  const data = createReadyToRunRendererFixture();
  const root = { type: 105, name: "DebugInfo", rva: 0, size: bytes.length };
  data.sections.push(root);
  const component = data.sections[3]!.decoded;
  assert.ok(component?.kind === "components");
  component.entries[0]!.coreHeader = { flags: 0, sectionCount: 1, sections: [{ ...root }] };
  const reader = new MockFile(bytes);
  const calls = test.mock.method(reader, "read");

  await decodeReadyToRunDebugSections(reader, rva => rva, data, 0x8664);

  assert.equal(calls.mock.calls.length, 1);
  assert.deepEqual(component.entries[0]!.coreHeader.sections[0]?.decoded,
    data.sections.at(-1)?.decoded);
  assert.deepEqual(data.issues, []);
});

void test("reports truncated storage and typed or untyped I/O failures", async () => {
  const data = createReadyToRunRendererFixture();
  data.sections = [{ type: 105, name: "DebugInfo", rva: 0, size: 7 }];
  const file = new MockFile(debugSection(new Uint8Array(), new Uint8Array()));

  await decodeReadyToRunDebugSections(file, rva => rva, data, undefined);
  file.read = async () => { throw new Error("disk failure"); };
  await decodeReadyToRunDebugSections(file, rva => rva, data, undefined);
  file.read = async () => { throw "disk failure"; };
  await decodeReadyToRunDebugSections(file, rva => rva, data, undefined);

  assert.match(data.issues.join(), /section is truncated/);
  assert.match(data.issues.join(), /disk failure/);
  assert.match(data.issues.join(), /section read failed/);
});
