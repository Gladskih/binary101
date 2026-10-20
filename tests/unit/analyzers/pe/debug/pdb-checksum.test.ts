"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePdbChecksumInfo } from "../../../../../analyzers/pe/debug/pdb-checksum.js";
import {
  createExtraDebugPayloadSubject,
  encodeNullTerminatedAscii,
  identityRvaToOff
} from "../../../../fixtures/pe-debug-extra-payloads.js";

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
  assert.match(warnings.join(" | "), /SHA256.*32 bytes/i);
});

void test("parsePdbChecksumInfo rejects empty algorithm names", async () => {
  const { result, warnings } = await parseSubject(Uint8Array.from([0x00, 0xaa]));

  assert.equal(result, null);
  assert.match(warnings.join(" | "), /algorithm name is empty/i);
});

void test("PDB checksums reject unsupported names and malformed UTF-8", async () => {
  const unsupported = await parseSubject(encodeNullTerminatedAscii("BLAKE3"));
  const invalid = await parseSubject(Uint8Array.from([255, 0]));
  const long = await parseSubject(encodeNullTerminatedAscii("unrecognized algorithm"));

  assert.equal(unsupported.result, null);
  assert.match(unsupported.warnings.join(" | "), /not supported/);
  assert.equal(invalid.result, null);
  assert.match(invalid.warnings.join(" | "), /not valid UTF-8/);
  assert.equal(long.result, null);
  assert.match(long.warnings.join(" | "), /not supported/);
});

[["SHA1", 20], ["SHA256", 32], ["SHA384", 48], ["SHA512", 64]].forEach(([name, size]) => {
  void test(`PDB checksum ${name} decodes its complete fixed-size digest`, async () => {
    const digest = new Uint8Array(Number(size)).fill(90);
    const { result, warnings } = await parseSubject(Uint8Array.from([
      ...encodeNullTerminatedAscii(String(name)), ...digest
    ]));

    assert.equal(result?.algorithmName, name);
    assert.deepEqual(result?.checksumBytes, [...digest]);
    assert.deepEqual(warnings, []);
  });
});

void test("PDB checksums use algorithm-defined digest lengths instead of reading huge malformed payloads", async () => {
  const payload = new Uint8Array(128 * 1024);
  payload.set(encodeNullTerminatedAscii("SHA256"));
  const subject = createExtraDebugPayloadSubject(payload);
  const reads: number[] = [];
  const warnings: string[] = [];
  const reader = { size: subject.file.size, readBytes: subject.file.readBytes.bind(subject.file),
    read: (offset: number, size: number) => { reads.push(size); return subject.file.read(offset, size); } };
  const result = await parsePdbChecksumInfo(reader, reader.size, identityRvaToOff,
    0, subject.offset, payload.length, message => warnings.push(message));

  assert.equal(result?.checksumBytes.length, 32);
  assert.ok(Math.max(...reads) <= 64);
  assert.match(warnings.join(" | "), /requires 32 bytes/);
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
