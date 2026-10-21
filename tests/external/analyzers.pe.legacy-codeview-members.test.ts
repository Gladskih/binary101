import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";
import { MockFile } from "../helpers/mock-file.js";

// Genuine embedded NB09 emitted by unchanged DMD 2.100.2 (-m32omf -g),
// compared with unchanged Microsoft cvdump at 805655a28bd8198004be2ac27e6e0290121a5e89.
// Source fixture: tests/external/pe-debug-native/LegacyMembers.d.
void test("real CodeView field, enum and method names agree with Microsoft's cvdump", async () => {
  const root = resolve("scan-results/pe-debug-native");
  const path = resolve(root, "Legacy-members.exe");
  const oracle = new TextDecoder("windows-1252").decode(execFileSync(resolve(root, "cvdump.exe"),
    ["-t", path], { maxBuffer: 8 * 1024 * 1024 }));
  const file = new MockFile(await readFile(path));
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const parsed = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const fields = parsed.entries.flatMap(entry => entry.legacyCodeView?.directories ?? [])
    .flatMap(directory => directory.subsections)
    .flatMap(section => section.data?.kind === "types" ? section.data.records : [])
    .flatMap(record => record.members ?? []);
  const names = fields.flatMap(field => field.name === undefined ? [] : [field.name]);
  const expected = [...oracle.matchAll(/(?:member name|name) = '([^']*)'/g)].map(match => match[1]!);

  assert.equal(expected.length, 7);
  assert.deepEqual(names, expected);
  assert.deepEqual(names, ["count", "ratio", "first", "last", "value", "this", "read"]);
  assert.deepEqual(fields.map(field => field.type), [0x406, 0x406, 0x403, 0x403, 0x400, 0x406, 0x408, 0x408]);
  assert.doesNotMatch(parsed.warning ?? "", /field list|type \d+:/i);
});
