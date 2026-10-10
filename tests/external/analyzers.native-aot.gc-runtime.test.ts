import assert from "node:assert/strict";
import { openAsBlob } from "node:fs";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../analyzers/pe/index.js";
import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { createPeNativeAotImage } from "../../analyzers/pe/native-aot/image.js";
import { parsePeHeaders, isPeWindowsCore } from "../../analyzers/pe/core/index.js";
import { NativeAotFunctionReferences } from "../../analyzers/native-aot/function-references.js";
import { NativeAotGcDescriptors, type NativeAotGcDescriptor } from "../../analyzers/native-aot/gc-descriptors.js";

const expected: Record<string, NativeAotGcDescriptor> = {
  references: { kind: "array-all-references", dataOffset: 16 },
  repeating: { kind: "array-repeating", firstReferenceOffset: 16, series: [{ pointerCount: 3, skipBytes: 16 }] },
  multidimensional: { kind: "array-repeating", firstReferenceOffset: 32, series: [{ pointerCount: 3, skipBytes: 16 }] },
  boxed: { kind: "object", series: [{ offset: 8, bytes: 24 }] }
};

const checkRuntimeType = async (line: string, references: NativeAotFunctionReferences): Promise<void> => {
  const [name, rva, flags, baseSize, numVtableSlots, hex] = line.split(" ");
  const type = { rva: Number(rva), flags: Number(flags), baseSize: Number(baseSize),
    numVtableSlots: Number(numVtableSlots) };
  assert.ok(expected[name!], "Unexpected runtime sample type");
  const bytes = Buffer.from(hex!, "hex");
  for (let offset = 0; offset < bytes.length; offset += 4) {
    assert.equal(await references.data.unsigned(type.rva - bytes.length + offset, 4),
      bytes.readUInt32LE(offset), `${name} hydrated word ${offset}`);
  }
  assert.deepEqual(await new NativeAotGcDescriptors(references).read(type), expected[name!], name!);
};

// dotnet publish tests/external/aot-gc-sample -r win-x64 -o <dir>; run Sample.exe > runtime.txt.
void test("GC descriptors match bytes from a running NativeAOT .NET 10 runtime", async context => {
  const path = process.env["BINARY101_NATIVE_AOT_GC_SAMPLE"];
  const output = process.env["BINARY101_NATIVE_AOT_GC_RUNTIME"];
  if (!path || !output) { context.skip("Set NativeAOT GC sample and runtime-output paths."); return; }
  const file = new File([await openAsBlob(path)], "gc-sample");
  const parsed = await parsePe(file);
  assert.ok(parsed && isPeWindowsParseResult(parsed) && parsed.nativeAotCandidate?.status === "confirmed");
  const reader = createFileRangeReader(file, 0, file.size);
  const core = await parsePeHeaders(reader);
  assert.ok(core && isPeWindowsCore(core));
  const image = createPeNativeAotImage(reader, core, 8, 10);
  const issues = new Set<string>();
  const references = new NativeAotFunctionReferences(image, parsed.nativeAotCandidate.sections, issues);
  const lines = (await readFile(output, "utf8")).trim().split(/\r?\n/);
  assert.equal(lines.length, 4);
  for (const line of lines) await checkRuntimeType(line, references);
  assert.deepEqual([...issues], []);
});
