import assert from "node:assert/strict";
import { test } from "node:test";
import { validateDebugEntry, validatePortablePdbLinks } from "../../../../../analyzers/pe/debug/entry-validation.js";
import { createDebugViewEntry } from "../../../../fixtures/pe-debug-view-subject.js";
import { parsePortablePdb } from "../../../../../analyzers/pe/debug/portable-pdb.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { createPortablePdbRoot, createPortablePdbStreams } from "../../../../fixtures/portable-pdb.js";

void test("debug entry diagnoses conflicting addresses and Portable PDB age", () => {
  const entry = { ...createDebugViewEntry(2, 128, 256, 24), minorVersion: 0x504d,
    codeView: { signature: "RSDS" as const, guid: "", age: 2, path: "" } };

  const warnings = validateDebugEntry(entry, value => value, 512);

  assert.match(warnings.join(" | "), /PointerToRawData.*disagree/);
  assert.match(warnings.join(" | "), /age.*1/i);
});

void test("unknown debug payloads are explicitly reported as unsupported", () => {
  const entry = createDebugViewEntry(65535, 0, 128, 8);

  assert.match(validateDebugEntry(entry, value => value, 512).join(" | "), /not decoded/i);
});

void test("SPGO directory type is unsupported even when no readable fallback bytes are available", () => {
  const entry = { ...createDebugViewEntry(18, 0, 128, 8), typeName: "SPGO" };

  assert.match(validateDebugEntry(entry, value => value, 512).join(" | "), /SPGO payload is not decoded/);
});

void test("debug versions and file bounds are diagnosed", () => {
  const entries = [
    createDebugViewEntry(17, 0, 128, 8),
    createDebugViewEntry(19, 0, 128, 8),
    createDebugViewEntry(21, 0, 128, 8),
    createDebugViewEntry(1, 0, 520, 8)
  ];
  const warnings = entries.flatMap(entry => validateDebugEntry(entry, value => value, 512));

  assert.match(warnings.join(" | "), /minor version 0x0100/);
  assert.match(warnings.join(" | "), /unsupported directory version/);
  assert.match(warnings.join(" | "), /exceeds the file bounds/);
});

void test("documented debug versions and matching raw addresses produce no warnings", () => {
  const entry = { ...createDebugViewEntry(19, 128, 128, 39), majorVersion: 1 };

  assert.deepEqual(validateDebugEntry(entry, value => value, 512), []);
  assert.deepEqual(validateDebugEntry(createDebugViewEntry(0, 0, 0, 0), () => null, 0), []);
});

void test("embedded PDB identity checks use both GUID and stamp", async () => {
  const pdb = await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), []);
  const embedded = { ...createDebugViewEntry(17, 0, 128, 8), embeddedPortablePdb: {
    signature: "MPDB", compressedSize: 8, uncompressedSize: 32, portablePdb: pdb!
  } };
  const codeView = { ...createDebugViewEntry(2, 0, 128, 24), minorVersion: 0x504d,
    codeView: { signature: "RSDS" as const, guid: pdb!.id.guid!, age: 1, path: "sample.pdb" } };

  assert.deepEqual(validatePortablePdbLinks([embedded, codeView]), []);
  assert.deepEqual(validatePortablePdbLinks([embedded]), []);
  assert.deepEqual(validatePortablePdbLinks([codeView]), []);
  assert.match(validatePortablePdbLinks([embedded, { ...codeView, timeDateStamp: 1 }]).join(" | "),
    /identity does not match/);
  assert.match(validatePortablePdbLinks([embedded, { ...codeView, codeView: {
    ...codeView.codeView, guid: "different"
  } }]).join(" | "), /identity does not match/);
});

void test("debug location warnings distinguish file-pointer presence and exact end bounds", () => {
  const entry = createDebugViewEntry(1, 0, 128, 384);

  assert.deepEqual(validateDebugEntry(entry, value => value, 512), []);
  assert.match(validateDebugEntry({ ...entry, sizeOfData: 385 }, value => value, 512).join(" | "),
    /exceeds the file bounds/);
  assert.deepEqual(validateDebugEntry({ ...entry, addressOfRawData: 256, pointerToRawData: 0 },
    value => value, 512), []);
  assert.deepEqual(validateDebugEntry({ ...entry, addressOfRawData: 0 }, () => null, 512), []);
});

void test("valid Portable PDB versions and ordinary CodeView do not acquire spurious warnings", () => {
  const ordinary = { ...createDebugViewEntry(2, 0, 128, 24), codeView: {
    signature: "RSDS" as const, guid: "", age: 2, path: "" } };

  assert.deepEqual(validateDebugEntry(ordinary, value => value, 512), []);
  assert.deepEqual(validateDebugEntry({ ...createDebugViewEntry(17, 0, 128, 8),
    minorVersion: 0x0100 }, value => value, 512), []);
  assert.match(validateDebugEntry({ ...createDebugViewEntry(17, 0, 128, 8),
    minorVersion: 0x0100, timeDateStamp: 1 }, value => value, 512).join(" | "), /zero timestamp/);
  assert.match(validateDebugEntry({ ...createDebugViewEntry(19, 0, 128, 8),
    majorVersion: 1, minorVersion: 1 }, value => value, 512).join(" | "), /unsupported directory version/);
});

void test("Portable CodeView rejects the legacy NB10 layout even with age one", () => {
  const entry = { ...createDebugViewEntry(2, 0, 128, 24), minorVersion: 0x504d,
    codeView: { signature: "NB10" as const, offset: 0, timestamp: 0, age: 1, path: "legacy.pdb" } };

  assert.match(validateDebugEntry(entry, value => value, 512).join(" | "), /requires an RSDS/);
});
