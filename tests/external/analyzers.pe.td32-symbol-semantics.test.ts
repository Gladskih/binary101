import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseTd32 } from "../../analyzers/pe/debug/td32.js";
import type { PeTd32Info } from "../../analyzers/pe/debug/td32.js";
import { analyzeTd32SymbolLinks } from "../../analyzers/pe/debug/td32-symbol-links.js";
import type { Td32SymbolMetadata, Td32SymbolRecord } from "../../analyzers/pe/debug/td32-symbol-types.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../fixtures/pe-debug-extra-payloads.js";

interface OracleFields {
  Offset?: number; Segment?: number; Register?: number; Size?: number; Length?: number;
  DebugStart?: number; DebugEnd?: number; Start?: number; Flags?: number; UsingCount?: number;
  Units?: string[]; Names?: string[]; Name?: string;
}
interface OracleSymbol { kind: string; fields: OracleFields; }
interface OracleOutput { names: string[]; modules: { symbols: OracleSymbol[] }[]; globals: OracleSymbol[]; }

const compareLocations = (metadata: Td32SymbolMetadata, oracle: OracleSymbol): void => {
  const fields = oracle.fields;
  if (metadata.location) assert.deepEqual(metadata.location, { offset: Number(fields.Offset) >>> 0,
    segment: Number(fields.Segment) & 0xffff }, oracle.kind);
  if (metadata.frameOffset !== undefined) assert.equal(metadata.frameOffset, fields.Offset);
  if (metadata.register !== undefined) assert.equal(metadata.register, Number(fields.Register) & 0xffff);
  if (metadata.codeLength !== undefined) assert.equal(metadata.codeLength, Number(fields.Size ?? fields.Length) >>> 0);
  if (metadata.debugRange) assert.deepEqual(metadata.debugRange, { start: fields.DebugStart, end: fields.DebugEnd });
  if (metadata.rangeStart !== undefined) assert.equal(metadata.rangeStart, Number(fields.Start ?? fields.Offset) >>> 0);
};

const compareSymbol = (record: Td32SymbolRecord, oracle: OracleSymbol, names: readonly string[]): void => {
  const metadata = record.metadata;
  if (!metadata) return;
  const fields = oracle.fields;
  compareLocations(metadata, oracle);
  if (metadata.flags !== undefined) assert.equal(metadata.flags, Number(fields.Flags) & 0xffff);
  if (metadata.usingCount !== undefined) assert.equal(metadata.usingCount, fields.UsingCount);
  if (metadata.nameIndices) assert.deepEqual(metadata.nameIndices.map(index => names[index - 1]),
    fields.Units ?? fields.Names);
  if (oracle.kind === "SymGDataRef") assert.equal(names[record.nameIndex! - 1], fields.Name);
};

const compareStream = (records: readonly Td32SymbolRecord[],
  oracle: readonly OracleSymbol[], names: readonly string[]) => {
  assert.equal(records.length, oracle.length);
  records.forEach((record, index) => compareSymbol(record, oracle[index]!, names));
};

const compareSections = (parsed: PeTd32Info, oracle: OracleOutput): void => {
  const sections = parsed.directories[0]!.subsections;
  const globals = sections.find(section => section.type === 0x129)!.data!;
  assert.ok(globals.kind === "symbols");
  compareStream(globals.records, oracle.globals, oracle.names);
  for (const section of sections.filter(section => section.type === 0x125)) {
    const data = section.data!;
    assert.ok(data.kind === "symbols");
    compareStream(data.records, oracle.modules[section.module - 1]!.symbols, oracle.names);
    assert.ok([...analyzeTd32SymbolLinks(data).values()].every(value => value.issues.length === 0));
  }
};

// Real C++Builder FB0A and unchanged map2dbg decoder; the adapter only exposes its scalar fields.
// TypeInfoFromId methods return null in upstream, so raw symbol type IDs are checked by independent unit vectors.
void test("real TD32 symbol sizes, locations, properties and imports agree with unchanged upstream", async () => {
  const path = resolve("scan-results/td32-public/arkanoid-Project1.tds");
  const oracle = JSON.parse(execFileSync(resolve("scan-results/td32-oracle.exe"),
    [resolve("scan-results/td32-upstream.dll"), path], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 })) as OracleOutput;
  const subject = createExtraDebugPayloadSubject(await readFile(path));
  const parsed = await parseTd32(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, subject.declaredSize, () => {});
  assert.ok(parsed);
  compareSections(parsed, oracle);
});
