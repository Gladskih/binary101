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
const assertRttiOnlyType = (
  parsed: PeWindowsParseResult, bytes: Buffer, map: string, encodedName: string, publishedName: string | null
): void => {
  // The link map is an independent oracle; the analyzed PE itself remains stripped.
  const match = new RegExp(`^\\s*(0x[0-9a-f]+)\\s+_ZTI${encodedName}\\s*$`, "m").exec(map);
  assert.ok(match, "The compiler must emit RTTI for the non-polymorphic class");
  assert.doesNotMatch(map, new RegExp(`\\b_ZTV${encodedName}\\b`));
  const rva = Number(BigInt(match[1]!) - parsed.opt.ImageBase);
  const section = parsed.sections.find(section => rva >= section.virtualAddress &&
    rva + 56 <= section.virtualAddress + section.sizeOfRawData);
  assert.ok(section);
  const offset = section.pointerToRawData + rva - section.virtualAddress;
  // x64 VMI: 2 bases at +20, private zero offsets at +32 and +48.
  assert.equal(bytes.readUInt32LE(offset + 20), 2);
  assert.equal(bytes.readBigUInt64LE(offset + 32), 0n);
  assert.equal(bytes.readBigUInt64LE(offset + 48), 0n);
  assert.equal(parsed.itaniumRtti!.types.find(type => type.address === rva)?.name ?? null, publishedName);
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
      assert.deepEqual(Object.keys(parsed.itaniumRtti).sort(), ["types", "warnings"]);
      const map = await readFile(mapPath, "utf8");
      assertRttiOnlyType(parsed, bytes, map, "8RttiOnly", "8RttiOnly");
      assertRttiOnlyType(parsed, bytes, map, "16RttiOnlyTemplateIiE", null);
      const longName = /\b_ZTI(16RttiOnlyTemplateISt16integer_sequence\w+)\b/.exec(map)?.[1];
      assert.ok(longName && longName.length > 511);
      assertRttiOnlyType(parsed, bytes, map, longName, null);
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
      assert.deepEqual(parsed.itaniumRtti.warnings, []);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}
