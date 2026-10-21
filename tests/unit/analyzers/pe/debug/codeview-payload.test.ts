import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCodeViewPayload } from "../../../../../analyzers/pe/debug/codeview-payload.js";
import { createLegacyCodeView } from "../../../../fixtures/pe-legacy-codeview.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../../../../fixtures/pe-debug-extra-payloads.js";

const decode = async (bytes: Uint8Array) => {
  const subject = createExtraDebugPayloadSubject(bytes);
  const warnings: string[] = [];
  return { decoded: await decodeCodeViewPayload(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, bytes.length, warning => warnings.push(warning)), warnings };
};

void test("CodeView dispatch recognizes inline NBxx without treating it as an external PDB pointer", async () => {
  const { decoded, warnings } = await decode(createLegacyCodeView());

  assert.equal(decoded.legacyCodeView?.signature, "NB09");
  assert.equal(decoded.codeView, undefined);
  assert.deepEqual(warnings, []);
});

void test("CodeView dispatch preserves NB10 paths and reports malformed headers", async () => {
  const nb10 = await decode(Uint8Array.from([78, 66, 49, 48, ...new Array<number>(12).fill(0), 65, 0]));
  const short = await decode(Uint8Array.from([78, 66, 48, 57]));
  const empty = await decode(new Uint8Array());

  assert.equal(nb10.decoded.codeView?.path, "A");
  assert.deepEqual(nb10.warnings, []);
  assert.deepEqual(short.decoded, {});
  assert.deepEqual(empty.decoded, {});
  assert.match(short.warnings.join(" | "), /bounds/);
});
