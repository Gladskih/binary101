import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { parseCoffObject } from "../../analyzers/coff/index.js";
import { readLegacyCodeViewModuleTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { buildCodeViewMemberTables } from "../../renderers/pe/codeview-member-tables.js";
import { codeViewInfoWithTypes } from "../fixtures/pe-codeview-callables.js";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";
import { MockFile } from "../helpers/mock-file.js";

void test("real MSVC bitfields retain LLVM widths, bit positions and member names", async () => {
  const object = resolve("scan-results/pe-debug-native/BitFields.obj");
  // Compile only; the target object is never executed. No Windows SDK headers are needed.
  execFileSync("C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/cl.exe",
    ["/nologo", "/TC", "/Z7", "/Od", "/c", resolve("tests/external/pe-debug-native/BitFields.c"), `/Fo${object}`]);
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--codeview", object]).toString("utf8");
  const bytes = await readFile(object);
  const coff = await parseCoffObject(new MockFile(bytes));
  const section = coff?.sections.find(value => value.name.value === ".debug$T");
  assert.ok(section);
  assert.ok(section.pointerToRawData + section.sizeOfRawData <= bytes.length);
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader(bytes.subarray(section.pointerToRawData,
    section.pointerToRawData + section.sizeOfRawData), warnings));
  const blocks = [...oracle.matchAll(/^ {2}BitField \(0x([0-9A-F]+)\) \{[^]*?^ {2}\}/gm)];
  assert.equal(blocks.length, 3);
  assert.deepEqual(parsed.records.filter(record => record.shape?.kind === "bitfield")
    .map(record => ({ index: record.index, shape: record.shape })), blocks.map(block => ({
      index: Number.parseInt(block[1]!, 16), shape: { kind: "bitfield",
        typeIndex: Number.parseInt(/^ {4}Type:.*\(0x([0-9A-F]+)\)/mi.exec(block[0])![1]!, 16),
        length: Number(/^ {4}BitSize: (\d+)/m.exec(block[0])![1]),
        position: Number(/^ {4}BitOffset: (\d+)/m.exec(block[0])![1]) }
    })));
  const rows = buildCodeViewMemberTables(codeViewInfoWithTypes(parsed.records))[0]!.rows;
  assert.deepEqual(rows.map(row => [row[3], row[4]]), [
    ["ready", "bitfield (bit width: 1, bit offset: 0) of uint32"],
    ["mode", "bitfield (bit width: 3, bit offset: 1) of uint32"],
    ["delta", "bitfield (bit width: 5, bit offset: 4) of int32"]
  ]);
  assert.deepEqual(warnings, []);
});
