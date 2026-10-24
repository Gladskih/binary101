import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { parseCoffObject } from "../../analyzers/coff/index.js";
import { readLegacyCodeViewModuleTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { codeViewVtableRecords } from "../fixtures/pe-codeview-vtables.js";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";
import { MockFile } from "../helpers/mock-file.js";

const alignedRecord = (record: number[]): number[] => {
  const padding = (4 - record.length % 4) % 4;
  for (let index = padding; index > 0; index--) record.push(0xf0 + index);
  record[0] = record.length - 2 & 255;
  record[1] = record.length - 2 >>> 8;
  return record;
};

const llvmReference = (block: string, field: string): number => {
  const value = new RegExp(`^ {4}${field}:.*(?:\\(0x([0-9A-F]+)\\)|0x([0-9A-F]+))$`, "mi").exec(block);
  assert.ok(value);
  return Number.parseInt(value[1] ?? value[2]!, 16);
};

void test("controlled vtable layouts agree with unchanged LLVM and Microsoft cvdump", async () => {
  const source = resolve("scan-results/pe-debug-native/Vtables.s");
  const object = resolve("scan-results/pe-debug-native/Vtables.obj");
  // These are explicit schema vectors assembled into COFF, not claimed compiler-generated layouts.
  await writeFile(source, '.section .debug$T,"dr"\n.long 4\n' + codeViewVtableRecords()
    .map(alignedRecord).map(record => `.byte ${record.join(",")}`).join("\n") + "\n");
  execFileSync("C:/Program Files/LLVM/bin/clang.exe", ["--target=x86_64-pc-windows-msvc", "-c", source, "-o", object]);
  const llvm = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--codeview", object]).toString("utf8");
  const microsoft = execFileSync(resolve("scan-results/pe-debug-native/cvdump.exe"), ["-t", object]).toString("utf8");
  const bytes = await readFile(object);
  const coff = await parseCoffObject(new MockFile(bytes));
  const section = coff?.sections.find(value => value.name.value === ".debug$T");
  assert.ok(section);
  const warnings: string[] = [];
  const types = await readLegacyCodeViewModuleTypes(legacyReader(bytes.subarray(section.pointerToRawData,
    section.pointerToRawData + section.sizeOfRawData), warnings));
  const blocks = [...llvm.matchAll(/^ {2}VFTable \(0x([0-9A-F]+)\) \{[^]*?^ {2}\}/gm)];
  assert.equal(blocks.length, 2);
  assert.deepEqual(types.records.filter(record => record.shape?.kind === "vtable")
    .map(record => ({ index: record.index, shape: record.shape, strings: record.strings })), blocks.map(block => ({
      index: Number.parseInt(block[1]!, 16), shape: { kind: "vtable", ownerType: llvmReference(block[0], "CompleteClass"),
        baseTable: llvmReference(block[0], "OverriddenVFTable"), pointerOffset: llvmReference(block[0], "VFPtrOffset") },
      strings: [...block[0].matchAll(/^ {4}(?:VFTableName|MethodName): (.*)$/gm)].map(value => value[1])
    })));
  assert.match(microsoft, /Type = 0x1001, base vftable = 0x1002, offset in object layout = 8/);
  assert.match(microsoft, /Unique name = <Derived>&amp;::table/);
  assert.deepEqual(warnings, []);
});
