import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseLegacyCodeView } from "../../analyzers/pe/debug/legacy-codeview.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../fixtures/pe-debug-extra-payloads.js";

// Unmodified Digital Mars DMD 2.100.2 -m32omf -g output, compared with Microsoft's
// unmodified cvdump.exe from microsoft-pdb commit 805655a28bd8198004be2ac27e6e0290121a5e89.
void test("real embedded NB09 retains all cvdump module, library and symbol names", async () => {
  const root = resolve("scan-results/pe-debug-native");
  const oracle = new TextDecoder("windows-1252").decode(execFileSync(resolve(root, "cvdump.exe"),
    ["-m", "-p", "-g", "-s", "-t", "-l", resolve(root, "Legacy-omf.exe")], { maxBuffer: 8 * 1024 * 1024 }));
  const subject = createExtraDebugPayloadSubject(await readFile(resolve(root, "codeview-legacy.bin")));
  const warnings: string[] = [];
  const parsed = await parseLegacyCodeView(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, subject.declaredSize, warning => warnings.push(warning));
  const data = parsed?.directories.flatMap(directory => directory.subsections).map(section => section.data) ?? [];
  const modules = [...oracle.matchAll(/^\d+\t([^\t\r\n]+)/gm)].map(match => match[1]!.trim());
  const libraries = [...oracle.matchAll(/^\s*\d+: {2}(.*)\r?$/gm)].map(match => match[1]!.trim());
  const publicNames = [...oracle.matchAll(/S_PUB32_16t:.*?Type:[^,]+, ([^\r\n]*)/g)].map(match => match[1]!);
  const sourceFiles = [...oracle.matchAll(/^ {2}(.+), [0-9A-F]{4}:[^\r\n]+line\/addr pairs = (\d+)/gm)]
    .map(match => ({ name: match[1]!, pairs: Number(match[2]) }));
  const typeKinds = [...oracle.matchAll(/Leaf = 0x([0-9a-f]+)/gi)].map(match => Number.parseInt(match[1]!, 16));

  assert.equal(parsed?.signature, "NB09");
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /ANSI code page is not recorded/);
  assert.equal(modules.length, 537);
  assert.deepEqual(data.flatMap(section => section?.kind === "module" ? [section.name] : []), modules);
  assert.deepEqual(data.flatMap(section => section?.kind === "libraries" ? section.names : []), libraries);
  assert.deepEqual(data.flatMap(section => section?.kind === "symbols" ? section.records : [])
    .filter(record => record.type === 0x203).map(record => record.name), publicNames);
  assert.equal(publicNames.length, 2008);
  assert.equal(data.find(section => section?.kind === "types")?.records.length, 7);
  assert.deepEqual(data.flatMap(section => section?.kind === "types" ? section.records.map(record => record.type) : []), typeKinds);
  assert.deepEqual(data.flatMap(section => section?.kind === "source" ? section.files.map(file => ({ name: file.name,
    pairs: file.segments.reduce((sum, segment) => sum + segment.lines.length, 0) })) : []), sourceFiles);
  assert.equal(sourceFiles.length, 2);
});
