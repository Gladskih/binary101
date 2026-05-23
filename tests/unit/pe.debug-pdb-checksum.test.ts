"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePdbChecksumInfo } from "../../analyzers/pe/debug/pdb-checksum.js";
import {
  createExtraDebugPayloadSubject,
  encodeNullTerminatedAscii,
  identityRvaToOff
} from "../fixtures/pe-debug-extra-payloads.js";

const parseSubject = async (payload: Uint8Array, declaredSize = payload.length) => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(payload, declaredSize);
  const result = await parsePdbChecksumInfo(
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

void test("parsePdbChecksumInfo decodes algorithm name and checksum bytes", async () => {
  // .NET PE/COFF addendum defines PDB checksum as NUL-terminated algorithm name
  // followed by checksum bytes.
  // https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md
  const algorithm = encodeNullTerminatedAscii("SHA256");
  const payload = new Uint8Array([...algorithm, 0xaa, 0xbb]);

  const { result, warnings } = await parseSubject(payload);

  assert.deepEqual(result, { algorithmName: "SHA256", checksumBytes: [0xaa, 0xbb] });
  assert.deepEqual(warnings, []);
});

void test("parsePdbChecksumInfo warns but preserves empty algorithm names", async () => {
  const { result, warnings } = await parseSubject(Uint8Array.from([0x00, 0xaa]));

  assert.deepEqual(result, { algorithmName: "", checksumBytes: [0xaa] });
  assert.match(warnings.join(" | "), /algorithm name is empty/i);
});

void test("parsePdbChecksumInfo rejects unterminated algorithm names", async () => {
  const { result, warnings } = await parseSubject(Uint8Array.from([0x53, 0x48, 0x41]));

  assert.equal(result, null);
  assert.match(warnings.join(" | "), /not NUL-terminated/i);
});

void test("parsePdbChecksumInfo reports truncated declared payloads", async () => {
  const algorithm = encodeNullTerminatedAscii("SHA256");

  const { result, warnings } = await parseSubject(algorithm, algorithm.length + 1);

  assert.deepEqual(result, { algorithmName: "SHA256", checksumBytes: [] });
  assert.match(warnings.join(" | "), /shorter than its declared SizeOfData/i);
});
