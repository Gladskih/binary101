import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePortablePdb } from "../../../../../analyzers/pe/debug/portable-pdb.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { createPortablePdbRoot, createPortablePdbStreams } from "../../../../fixtures/portable-pdb.js";

void test("Portable PDB decodes all eight tables, documents and sequence point statistics", async () => {
  const issues: string[] = [];
  const result = await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), issues);

  assert.equal(result?.tables.length, 8);
  assert.ok(result?.tables.every(table => table.declaredRows === 1 && table.parsedRows === 1));
  assert.deepEqual(result?.documents, [{ name: "source.cs",
    language: "3f5162f8-07c6-11d3-9053-00c04fa302a1",
    hashAlgorithm: "8829d00f-11b8-4213-878b-770e8597ac16", hashSize: 32 }]);
  assert.equal(result?.methodsWithSequencePoints, 1);
  assert.deepEqual(result?.sequencePoints, { visible: 1, hidden: 1 });
  assert.deepEqual(result?.locals, [
    { kind: "variable", name: "local", slot: 0, attributes: 0 },
    { kind: "constant", name: "constant", signatureSize: 5, constant: { typeCode: 8, value: 3 } }
  ]);
  assert.deepEqual(result?.customRecords, [{ kind: "cc110556-a091-4d38-9fec-25ab9a351a6a", size: 63,
    parent: { tableId: 0, row: 1 }, data: { type: "sourceLink", documents: [
      { pattern: "source.cs", url: "https://example.invalid/source.cs" }
    ] } }]);
  assert.deepEqual(result?.imports, [{ parent: 0, imports: [{ kind: 1, targetNamespace: "System" }] }]);
  assert.deepEqual(issues, []);
});

void test("Portable PDB retains import scope ancestry and namespace strings", async () => {
  const streams = createPortablePdbStreams();
  const previous = streams["#Blob"]!;
  const namespace = new TextEncoder().encode("System");
  streams["#Blob"] = Uint8Array.from([...previous, namespace.length, ...namespace,
    3, 1, 0x80 | (previous.length >> 8), previous.length & 255]);
  // ImportScope is after LocalConstant in the table stream; its Imports column is at +96.
  new DataView(streams["#~"]!.buffer).setUint16(96, previous.length + 1 + namespace.length, true);
  const issues: string[] = [];
  const result = await parsePortablePdb(new MockFile(createPortablePdbRoot(streams)), issues);

  assert.deepEqual(result?.imports, [{ parent: 0, imports: [{ kind: 1, targetNamespace: "System" }] }]);
  assert.deepEqual(issues, []);
});

void test("Portable PDB rejects truncated metadata without throwing", async () => {
  const issues: string[] = [];
  const result = await parsePortablePdb(new MockFile(new Uint8Array(3)), issues);

  assert.equal(result, null);
  assert.match(issues.join(" | "), /metadata.*truncated/i);
});

const parseStreams = async (streams: Record<string, Uint8Array>) => {
  const issues: string[] = [];
  const result = await parsePortablePdb(new MockFile(createPortablePdbRoot(streams)), issues);
  return { result, issues };
};

void test("Portable PDB preserves locals with unreadable names and constant signatures", async () => {
  const streams = createPortablePdbStreams();
  delete streams["#Strings"];
  // LocalConstant.Signature is the final word of its row, before ImportScope's two words.
  new DataView(streams["#~"]!.buffer).setUint16(92, 0xffff, true);
  const { result, issues } = await parseStreams(streams);

  assert.deepEqual(result?.locals, [
    { kind: "variable", name: null, slot: 0, attributes: 0 },
    { kind: "constant", name: null, signatureSize: null, constant: null }
  ]);
  assert.match(issues.join(" | "), /outside the heap/);
});

void test("Portable PDB requires both standalone metadata streams", async () => {
  const { result, issues } = await parseStreams({ "#Pdb": new Uint8Array(32) });

  assert.equal(result, null);
  assert.match(issues.join(" | "), /requires both/);
});

void test("Portable PDB rejects truncated #Pdb and row-count arrays", async () => {
  const streams = createPortablePdbStreams();
  streams["#Pdb"] = new Uint8Array(4);
  const short = await parseStreams(streams);
  streams["#Pdb"] = new Uint8Array(32).fill(255, 24);
  const counts = await parseStreams(streams);

  assert.equal(short.result, null);
  assert.match(short.issues.join(" | "), /#Pdb header is truncated/);
  assert.equal(counts.result, null);
  assert.match(counts.issues.join(" | "), /row counts are truncated/);
});

void test("Portable PDB refuses out-of-bounds stream spans and wrong signatures", async () => {
  const bytes = createPortablePdbRoot(createPortablePdbStreams());
  // Root fixture's 12-byte version is followed by flags/count, then the first stream header.
  new DataView(bytes.buffer).setUint32(32, bytes.length + 1, true);
  const issues: string[] = [];
  const result = await parsePortablePdb(new MockFile(bytes), issues);
  bytes[0] = 0;
  const wrongSignature = await parsePortablePdb(new MockFile(bytes), []);

  assert.equal(result, null);
  assert.match(issues.join(" | "), /stream extends outside/);
  assert.equal(wrongSignature, null);
});

void test("Portable PDB reports unsupported type-system tables", async () => {
  const streams = createPortablePdbStreams();
  const tables = new Uint8Array(28);
  // #~ header Valid bit 0 declares an empty Module table, disallowed in standalone PDB.
  new DataView(tables.buffer).setBigUint64(8, 1n, true);
  streams["#~"] = tables;
  const pdb = streams["#Pdb"]!;
  new DataView(pdb.buffer).setBigUint64(24, 1n << 63n, true);
  const { result, issues } = await parseStreams(streams);

  assert.ok(result);
  assert.match(issues.join(" | "), /invalid type-system table/);
  assert.match(issues.join(" | "), /non-debug metadata/);
});

void test("Portable PDB preserves diagnostics for unreadable document and sequence-point blobs", async () => {
  const streams = createPortablePdbStreams();
  streams["#Blob"] = Uint8Array.of(0);
  const { result, issues } = await parseStreams(streams);

  assert.equal(result?.documents[0]?.name, null);
  assert.equal(result?.methodsWithSequencePoints, 0);
  assert.match(issues.join(" | "), /outside the heap/);
});

void test("Portable PDB diagnoses malformed document-name indexes and UTF-8 separators", async () => {
  const streams = createPortablePdbStreams();
  const nameIndex = new DataView(streams["#~"]!.buffer).getUint16(56, true);
  streams["#Blob"]![nameIndex + 2] = 0xff;
  const malformedIndex = await parseStreams(streams);
  streams["#Blob"]![nameIndex + 1] = 0xff;
  const malformedSeparator = await parseStreams(streams);

  assert.equal(malformedIndex.result?.documents[0]?.name, null);
  assert.match(malformedIndex.issues.join(" | "), /malformed blob index/);
  assert.equal(malformedSeparator.result?.documents[0]?.name, null);
  assert.match(malformedSeparator.issues.join(" | "), /not valid UTF-8/);
});

void test("Portable PDB rejects truncated table headers and retains complete rows before truncation", async () => {
  const streams = createPortablePdbStreams();
  streams["#~"] = new Uint8Array(4);
  const header = await parseStreams(streams);
  streams["#~"] = createPortablePdbStreams()["#~"]!.slice(0, 60);
  const rows = await parseStreams(streams);

  assert.equal(header.result, null);
  assert.match(header.issues.join(" | "), /smaller.*table header/);
  assert.equal(rows.result?.tables[0]?.parsedRows, 0);
  assert.match(rows.issues.join(" | "), /Document is truncated/);
});

["§", "∕", "😀"].forEach(separator => {
  void test(`Portable PDB document names support UTF-8 separator ${separator}`, async () => {
    const streams = createPortablePdbStreams();
    const previous = streams["#Blob"]!;
    const bytes = new TextEncoder().encode(separator);
    streams["#Blob"] = Uint8Array.from([...previous, bytes.length + 2, ...bytes, 1, 1]);
    new DataView(streams["#~"]!.buffer).setUint16(56, previous.length, true);
    const { result, issues } = await parseStreams(streams);

    assert.equal(result?.documents[0]?.name, `source.cs${separator}source.cs`);
    assert.deepEqual(issues, []);
  });
});

void test("Portable PDB diagnoses invalid document parts and preserves nil sequence-point blobs", async () => {
  const streams = createPortablePdbStreams();
  const table = new DataView(streams["#~"]!.buffer);
  const previous = streams["#Blob"]!;
  streams["#Blob"] = Uint8Array.from([...previous, 3, 47, 0xbf, 0xff]); // Part index 16383 is outside #Blob.
  table.setUint16(56, previous.length, true);
  table.setUint16(66, 0, true); // MethodDebugInformation.SequencePoints follows the Document index.
  const { result, issues } = await parseStreams(streams);

  assert.equal(result?.documents[0]?.name, null);
  assert.equal(result?.methodsWithSequencePoints, 0);
  assert.match(issues.join(" | "), /outside the heap/);
});

void test("Portable PDB diagnoses invalid UTF-8 within document name parts", async () => {
  const streams = createPortablePdbStreams();
  streams["#Blob"]![2] = 255; // First part's UTF-8 data, after its compressed length.
  const { result, issues } = await parseStreams(streams);

  assert.equal(result?.documents[0]?.name, null);
  assert.match(issues.join(" | "), /not valid UTF-8/);
});

void test("Portable PDB decodes shared sequence-point blobs once per document context", async () => {
  const streams = createPortablePdbStreams();
  const previous = streams["#~"]!;
  const points = new DataView(previous.buffer).getUint16(66, true);
  streams["#Blob"]![points + 3] = 255; // Malformed compressed line delta.
  streams["#~"] = Uint8Array.from([...previous.slice(0, 68), ...previous.slice(64, 68), ...previous.slice(68)]);
  new DataView(streams["#~"]!.buffer).setUint32(28, 2, true); // Two MethodDebugInformation rows.
  new DataView(streams["#Pdb"]!.buffer).setUint32(36, 2, true); // Two referenced MethodDef rows.
  const { result, issues } = await parseStreams(streams);

  assert.equal(result?.methodsWithSequencePoints, 2);
  assert.equal(issues.filter(issue => issue.includes("sequence points")).length, 1);
});
