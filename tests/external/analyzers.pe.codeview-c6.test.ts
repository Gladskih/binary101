import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createC6CodeView, c6Sections } from "../fixtures/pe-codeview-c6.js";
import { createLegacyCodeView } from "../fixtures/pe-legacy-codeview.js";
import { createPeWithDebugPayloads } from "../fixtures/pe-debug-file.js";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";

// Controlled PE fixtures, not historical compiler output. Microsoft's unchanged
// prebuilt cvdump has the NB02 10/12-byte packing bug reported in upstream PR #43.
// A NB05 directory envelope lets its unchanged old-subsection readers consume the
// identical C6 module/public/library/line bytes. Its C6 type reader is also broken
// (unsigned Leaf_pos = -3 in type6.cpp), so this test does not claim a type oracle.
// https://github.com/microsoft/microsoft-pdb/pull/43
// cvdump.exe: microsoft-pdb@805655a28bd8198004be2ac27e6e0290121a5e89
void test("C6 PE module, public, library and source names agree with unchanged Microsoft readers", async () => {
  const sections = c6Sections();
  const file = createPeWithDebugPayloads([{ type: 2, data: createC6CodeView(sections) }]);
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const data = debug.entries[0]!.legacyCodeView!.directories[0]!.subsections.map(section => section.data);
  const temporary = await mkdtemp(join(tmpdir(), "binary101-c6-"));
  try {
    const path = join(temporary, "controlled-c6-envelope.exe");
    const envelope = createLegacyCodeView(sections, "NB05");
    await writeFile(path, createPeWithDebugPayloads([{ type: 2, data: envelope }]).data);
    const oracle = new TextDecoder("windows-1252").decode(execFileSync(
      resolve("scan-results/pe-debug-native/cvdump.exe"), ["-m", "-p", "-l", path],
      { timeout: 5000, maxBuffer: 1024 * 1024 }));
    assert.equal(debug.warning, null);
    assert.equal(data[0]?.kind, "module");
    assert.ok(oracle.includes(data[0].name));
    assert.equal(data[1]?.kind, "publics");
    assert.ok(oracle.includes(data[1].names[0]!));
    assert.equal(data[4]?.kind, "libraries");
    assert.ok(oracle.includes(data[4].names[1]!));
    assert.equal(data[5]?.kind, "oldLines");
    assert.ok(oracle.includes(data[5].files[0]!.name));
    assert.match(oracle, /count =\s+2:/);
  } finally { await rm(temporary, { recursive: true, force: true }); }
});
