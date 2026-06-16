"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCodeViewEntry } from "../../../../../analyzers/pe/debug/codeview.js";
import {
  createExtraDebugPayloadSubject,
  encodeNullTerminatedAscii,
  identityRvaToOff,
  writeU32
} from "../../../../fixtures/pe-debug-extra-payloads.js";

const NB10_SIGNATURE = 0x3031424e;
const NB10_HEADER_SIZE = 16;

const createNb10Payload = (pathBytes: Uint8Array): Uint8Array => {
  const bytes = new Uint8Array(NB10_HEADER_SIZE + pathBytes.length);
  writeU32(bytes, 0, NB10_SIGNATURE);
  writeU32(bytes, 4, 0);
  writeU32(bytes, 8, 0x3aef6cec);
  writeU32(bytes, 12, 1);
  bytes.set(pathBytes, NB10_HEADER_SIZE);
  return bytes;
};

const parseSubject = async (payload: Uint8Array, declaredSize = payload.length) => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(payload, declaredSize);
  const result = await parseCodeViewEntry(
    subject.file,
    subject.file.size,
    identityRvaToOff,
    0,
    subject.offset,
    subject.declaredSize,
    message => warnings.push(message)
  );
  return { result, warnings };
};

void test("parseCodeViewEntry decodes legacy NB10 records", async () => {
  // NB10 is the legacy CodeView PDB pointer observed in Windows crtdll.dll.
  const { result, warnings } = await parseSubject(createNb10Payload(encodeNullTerminatedAscii("crtdll.pdb")));

  assert.deepEqual(result, {
    signature: "NB10",
    offset: 0,
    timestamp: 0x3aef6cec,
    age: 1,
    path: "crtdll.pdb"
  });
  assert.deepEqual(warnings, []);
});

void test("parseCodeViewEntry reports unterminated NB10 paths but preserves text", async () => {
  const { result, warnings } = await parseSubject(createNb10Payload(new TextEncoder().encode("crtdll.pdb")));

  assert.equal(result?.path, "crtdll.pdb");
  assert.match(warnings.join(" | "), /not NUL-terminated/i);
});

void test("parseCodeViewEntry rejects CodeView payloads smaller than NB10", async () => {
  const { result, warnings } = await parseSubject(new Uint8Array(NB10_HEADER_SIZE - 1));

  assert.equal(result, null);
  assert.match(warnings.join(" | "), /smaller than the minimum NB10 header/i);
});

void test("parseCodeViewEntry rejects unknown CodeView signatures with a warning", async () => {
  const payload = createNb10Payload(encodeNullTerminatedAscii("bad.pdb"));
  writeU32(payload, 0, 0x21444142);

  const { result, warnings } = await parseSubject(payload);

  assert.equal(result, null);
  assert.match(warnings.join(" | "), /signature is not RSDS or NB10/i);
});

void test("parseCodeViewEntry rejects payloads that extend beyond file bounds", async () => {
  const payload = createNb10Payload(encodeNullTerminatedAscii("short.pdb"));

  const { result, warnings } = await parseSubject(payload, payload.length + 1);

  assert.equal(result, null);
  assert.match(warnings.join(" | "), /outside file bounds/i);
});
