import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, rmdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";
import { createPeWithDebugPayloads } from "../fixtures/pe-debug-file.js";
import { createMpxPayload, createSpgoPayload } from "../fixtures/pe-debug-optimization.js";

void test("controlled MPX and SPGO records agree with unchanged Microsoft dumpbin", {
  skip: !process.env["DUMPBIN"]
}, async () => {
  const file = createPeWithDebugPayloads([
    { type: 14, data: new Uint8Array() },
    { type: 15, data: createMpxPayload() },
    { type: 18, data: createSpgoPayload("sample.spd") }
  ]);
  const directory = await mkdtemp(join(tmpdir(), "binary101-debug-optimization-"));
  try {
    const path = join(directory, "controlled.exe");
    await writeFile(path, file.data);
    // Inspect only: never execute the generated PE. This is a controlled-layout
    // comparison, not a claim that a compiler naturally emitted these records.
    const native = execFileSync(process.env["DUMPBIN"]!, ["/headers", path], {
      encoding: "utf8", timeout: 10_000, maxBuffer: 1024 * 1024
    });
    const core = await parsePeHeaders(file);
    assert.ok(core);
    const parsed = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
    assert.match(native, /iltcg\s+0\s/);
    assert.match(native, /mpx\s+14\s+[^\r\n]*Flags:\s+5/);
    assert.match(native, /spgo\s+16\s+[^\r\n]*sample\.spd/);
    assert.deepEqual(parsed.entries.map(entry => entry.type), [14, 15, 18]);
    assert.equal(parsed.entries[1]?.mpx?.flags, 5);
    assert.equal(parsed.entries[2]?.spgo?.text, "sample.spd");
    assert.equal(parsed.warning, null);
  } finally {
    await rm(join(directory, "controlled.exe"), { force: true });
    await rmdir(directory);
  }
});
