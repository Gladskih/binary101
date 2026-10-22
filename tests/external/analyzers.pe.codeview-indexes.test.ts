import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";
import { MockFile } from "../helpers/mock-file.js";
import { createPeWithDebugPayloads } from "../fixtures/pe-debug-file.js";
import { createLegacyCodeView, legacySymbol } from "../fixtures/pe-legacy-codeview.js";
import { codeViewHashIndex, codeViewAddressIndex, codeViewGlobalSymbols } from "../fixtures/pe-codeview-hash-index.js";

// Unchanged Microsoft cvdump at 805655a28bd8198004be2ac27e6e0290121a5e89.
// For genuine DMD NB09 files, compare each complete bucket and section inventory.
// cvdump narrows DWORD bucket counts to WORD internally; these real counts fit WORD.
const verifyIndexes = async (file: MockFile, path: string): Promise<void> => {
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const parsed = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const indexes = parsed.entries.flatMap(entry => entry.legacyCodeView?.directories ?? [])
    .flatMap(directory => directory.subsections)
    .flatMap(section => section.data?.kind === "symbols" && section.data.nameIndex ? [section.data] : []);
  const oracle = execFileSync(resolve("scan-results/pe-debug-native/cvdump.exe"), ["-g", "-p", path],
    { maxBuffer: 16 * 1024 * 1024 }).toString("utf8");
  const blocks = oracle.split(/^\*\*\* /m).filter(block => /^(Global Publics|Compacted Global Symbols) section/.test(block));

  assert.ok(indexes.length > 0);
  assert.equal(indexes.length, blocks.length);
  indexes.forEach((symbols, index) => {
    const block = blocks[index]!;
    assert.equal(symbols.nameIndex!.algorithm, Number(/Symbol hash function index = (\d+)/.exec(block)![1]));
    assert.equal(symbols.addressIndex!.algorithm, Number(/Adress hash function index = (\d+)/.exec(block)![1]));
    assert.deepEqual(symbols.nameIndex!.counts,
      [...block.matchAll(/Bucket = [\dA-F]+, Count = ([\dA-F]+)/g)].map(match => Number.parseInt(match[1]!, 16)));
    assert.deepEqual(symbols.addressIndex!.counts,
      [...block.matchAll(/Segment #\d+ - (\d+) symbols/g)].map(match => Number(match[1])));
  });
  assert.doesNotMatch(parsed.warning ?? "", /index|hash tables/i);
};

for (const name of ["Legacy-omf.exe", "Legacy-members.exe"]) {
  void test(`real DMD name hashes and address indexes match Microsoft's cvdump: ${name}`, async () => {
    const path = resolve("scan-results/pe-debug-native", name);

    await verifyIndexes(new MockFile(await readFile(path)), path);
  });
}

// Controlled layouts for old 32-bit algorithms, checked by unchanged cvdump.
// These are explicitly synthesized fixtures, not claimed compiler-produced records.
for (const [nameAlgorithm, addressAlgorithm] of [[2, 4], [6, 5], [2, 8]]) {
  void test(`old CodeView index layouts agree with cvdump: ${nameAlgorithm}/${addressAlgorithm}`, async () => {
    const file = createPeWithDebugPayloads([{ type: 2, data: createLegacyCodeView([
      { type: 0x12a, module: 0xffff, data: Uint8Array.from(codeViewGlobalSymbols(legacySymbol(),
        codeViewHashIndex([0, 2, 1], 2, 4), codeViewAddressIndex([1, 0, 2], addressAlgorithm!),
        nameAlgorithm, addressAlgorithm)) }
    ]) }]);
    const path = resolve(`scan-results/pe-debug-native/codeview-index-${nameAlgorithm}-${addressAlgorithm}.exe`);
    await writeFile(path, file.data);

    await verifyIndexes(file, path);
  });
}
