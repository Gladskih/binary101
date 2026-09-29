import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { isPeWindowsParseResult, parsePe } from "../../analyzers/pe/index.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import { MockFile } from "../helpers/mock-file.js";

const compiler = process.env["MINGW_CXX"] ?? "C:/msys64/ucrt64/bin/g++.exe";
const assertRttiOnlyOmitted = (parsed: PeWindowsParseResult, bytes: Buffer, map: string): void => {
  // The link map is an independent oracle; the analyzed PE itself remains stripped.
  const match = /^\s*(0x[0-9a-f]+)\s+_ZTI8RttiOnly\s*$/m.exec(map);
  assert.ok(match, "The compiler must emit RTTI for the non-polymorphic class");
  assert.doesNotMatch(map, /\b_ZTV8RttiOnly\b/);
  const rva = Number(BigInt(match[1]!) - parsed.opt.ImageBase);
  const section = parsed.sections.find(section => rva >= section.virtualAddress &&
    rva + 56 <= section.virtualAddress + section.sizeOfRawData);
  assert.ok(section);
  const offset = section.pointerToRawData + rva - section.virtualAddress;
  // x64 VMI: 2 bases at +20, private zero offsets at +32 and +48.
  assert.equal(bytes.readUInt32LE(offset + 20), 2);
  assert.equal(bytes.readBigUInt64LE(offset + 32), 0n);
  assert.equal(bytes.readBigUInt64LE(offset + 48), 0n);
  assert.equal(parsed.itaniumRtti!.vtables.some(table => table.address >= rva &&
    table.address < rva + 56), false);
  assert.equal(parsed.itaniumRtti!.types.some(type => type.address === rva), false);
};
for (const optimization of ["-O0", "-O2"]) {
  void test(`recognizes real stripped static MinGW RTTI (${optimization})`, {
    skip: !existsSync(compiler)
  }, async () => {
    const directory = await mkdtemp(join(tmpdir(), "binary101-itanium-"));
    try {
      const executable = join(directory, "fixture.exe");
      const mapPath = join(directory, "fixture.map");
      execFileSync(compiler, [resolve("samples/pe-disassembly/cpp/itanium-rtti.cpp"),
        "-o", executable, optimization, "-static", "-s", "-Wl,--dynamicbase",
        `-Wl,-Map=${mapPath},--no-demangle`], {
        env: { ...process.env, PATH: dirname(compiler) + ";" + process.env["PATH"] }
      });
      const bytes = await readFile(executable);
      const parsed = await parsePe(new MockFile(bytes));
      assert.ok(parsed && isPeWindowsParseResult(parsed));
      assert.ok(parsed.itaniumRtti);
      assertRttiOnlyOmitted(parsed, bytes, await readFile(mapPath, "utf8"));
      const types = new Map(parsed.itaniumRtti.types.map(type => [type.name, type]));
      assert.equal(types.get("4Base")?.kind, "class");
      assert.equal(types.get("7Derived")?.kind, "si");
      assert.equal(types.get("8Multiple")?.bases.length, 2);
      assert.equal(types.get("7Virtual")?.bases[0]?.isVirtual, true);
      const collision = types.get("9Collision");
      assert.ok(collision);
      assert.deepEqual(collision.bases, [
        { typeAddress: types.get("6EmptyA")!.address, offset: 0, isVirtual: false, isPublic: false },
        { typeAddress: types.get("6EmptyB")!.address, offset: 0, isVirtual: false, isPublic: false }
      ]);
      // x64 VMI +48 is base1.offset_flags, not a vtable address point.
      assert.equal(parsed.itaniumRtti.vtables.some(table => table.address === collision.address + 48), false);
      assert.deepEqual(parsed.itaniumRtti.warnings, []);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}
