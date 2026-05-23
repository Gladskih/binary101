"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseEmbeddedPortablePdbInfo } from "../../analyzers/pe/debug/embedded-portable-pdb.js";
import { createExtraDebugPayloadSubject, identityRvaToOff, writeU32 } from "../fixtures/pe-debug-extra-payloads.js";

const MPDB_SIGNATURE = 0x4244504d;

const createPayload = (signature: number, uncompressedSize: number, compressedBytes: number[]): Uint8Array => {
  const bytes = new Uint8Array(8 + compressedBytes.length);
  writeU32(bytes, 0, signature);
  writeU32(bytes, 4, uncompressedSize);
  bytes.set(compressedBytes, 8);
  return bytes;
};

const parseSubject = async (payload: Uint8Array, declaredSize = payload.length) => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(payload, declaredSize);
  const result = await parseEmbeddedPortablePdbInfo(
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

void test("parseEmbeddedPortablePdbInfo decodes MPDB header sizes", async () => {
  // .NET PE/COFF addendum defines Embedded Portable PDB data as MPDB +
  // uncompressed size + deflate payload.
  // https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md
  const { result, warnings } = await parseSubject(createPayload(MPDB_SIGNATURE, 4, [0x78, 0x9c]));

  assert.deepEqual(result, { signature: "MPDB", uncompressedSize: 4, compressedSize: 2 });
  assert.deepEqual(warnings, []);
});

void test("parseEmbeddedPortablePdbInfo rejects payloads smaller than the fixed header", async () => {
  const { result, warnings } = await parseSubject(Uint8Array.from([0x4d, 0x50, 0x44]));

  assert.equal(result, null);
  assert.match(warnings.join(" | "), /smaller than the fixed header/i);
});

void test("parseEmbeddedPortablePdbInfo warns on wrong signature and reserved zero size", async () => {
  const { result, warnings } = await parseSubject(createPayload(0x21444142, 0, []));

  assert.deepEqual(result, { signature: "BAD!", uncompressedSize: 0, compressedSize: 0 });
  assert.match(warnings.join(" | "), /signature is not MPDB/i);
  assert.match(warnings.join(" | "), /uncompressed size is 0/i);
});

void test("parseEmbeddedPortablePdbInfo reports truncated declared payloads", async () => {
  const payload = createPayload(MPDB_SIGNATURE, 4, []);

  const { result, warnings } = await parseSubject(payload, payload.length + 1);

  assert.deepEqual(result, { signature: "MPDB", uncompressedSize: 4, compressedSize: 0 });
  assert.match(warnings.join(" | "), /shorter than its declared SizeOfData/i);
});
