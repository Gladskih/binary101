import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseFixupInfo } from "../../analyzers/pe/debug/fixup.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../fixtures/pe-debug-extra-payloads.js";

// Real MSVC linker-produced FIXUP stream, exported unchanged with llvm-pdbutil.
// The current linker stores it in the PDB, so this checks the payload layout rather
// than claiming that the EXE contains an IMAGE_DEBUG_TYPE_FIXUP directory entry.
void test("MSVC XFIXUP payload agrees with unchanged Microsoft cvdump", { skip: process.platform !== "win32" }, async () => {
  const artifact = resolve("scan-results/pe-debug-native");
  const output = execFileSync(resolve(artifact, "cvdump.exe"), ["-fixup", resolve(artifact, "Fixup.pdb")],
    { encoding: "utf8" });
  const expected = [...output.matchAll(/^\s+([0-9A-F]{4})\s+([0-9A-F]{4})\s+([0-9A-F]{8})\s+([0-9A-F]{8})\s*$/gm)]
    .map(match => ({ type: Number.parseInt(match[1]!, 16), extra: Number.parseInt(match[2]!, 16),
      rva: Number.parseInt(match[3]!, 16), targetRva: Number.parseInt(match[4]!, 16) }));
  const subject = createExtraDebugPayloadSubject(await readFile(resolve(artifact, "fixup.bin")));
  const issues: string[] = [];
  const result = await parseFixupInfo(subject.file, subject.file.size, identityRvaToOff, 0, subject.offset,
    subject.declaredSize, issue => issues.push(issue));

  assert.ok(expected.length > 0);
  assert.deepEqual(result?.records, expected);
  assert.deepEqual(issues, []);
});
