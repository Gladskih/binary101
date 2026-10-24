import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { parseCoffObject } from "../../analyzers/coff/index.js";
import { readLegacyCodeViewModuleTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";
import { MockFile } from "../helpers/mock-file.js";

void test("real MSVC type-server GUID, PDB age and file match unchanged LLVM", async () => {
  const object = resolve("scan-results/pe-debug-native/TypeServerReference.obj");
  const database = resolve("scan-results/pe-debug-native/TypeServerReference.pdb");
  execFileSync("C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/cl.exe",
    ["/nologo", "/TP", "/Zi", "/c", `/Fd${database}`, `/Fo${object}`,
      resolve("tests/external/pe-debug-native/CompositeTypes.cpp")]);
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--codeview", object]).toString("utf8");
  const guid = /^ {4}Guid: \{([^}]+)\}$/m.exec(oracle);
  const age = /^ {4}Age: (\d+)$/m.exec(oracle);
  const name = /^ {4}Name: (.*)$/m.exec(oracle);
  assert.ok(guid && age && name);
  const bytes = await readFile(object);
  const coff = await parseCoffObject(new MockFile(bytes));
  const section = coff?.sections.find(value => value.name.value === ".debug$T");
  assert.ok(section);
  const warnings: string[] = [];
  const types = await readLegacyCodeViewModuleTypes(legacyReader(bytes.subarray(section.pointerToRawData,
    section.pointerToRawData + section.sizeOfRawData), warnings));
  assert.deepEqual(types.records, [{ type: 0x1515, strings: [name[1]], shape: { kind: "typeServer",
    identity: { kind: "guid", value: guid[1]!.toLowerCase() }, age: Number(age[1]) } }]);
  assert.deepEqual(warnings, []);
});
