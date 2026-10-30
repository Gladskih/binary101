import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { parseWasm } from "../../../../analyzers/wasm/index.js";
import { parseForUi } from "../../../../analyzers/index.js";
import { createWasmFile, wasmModule, wasmSection, wasmString, wasmUnsigned } from "../../../fixtures/wasm-fixtures.js";

void test("deeply parses a valid executable module without executing it", async () => {
  const file = createWasmFile();
  assert.equal(WebAssembly.validate(await file.arrayBuffer()), true);
  const result = await parseWasm(file);
  assert.ok(result);
  assert.deepEqual(result.issues, []);
  assert.equal(result.moduleName, "analysis-demo");
  assert.equal(result.sections.length, 14);
  assert.equal(result.types.length, 3);
  assert.equal(result.imports[0]?.name, "log");
  assert.equal(result.exports[0]?.name, "add");
  assert.equal(result.functions[0]?.typeIndex, 1);
  assert.equal(result.code[0]?.instructions[2]?.mnemonic, "i32.add");
  assert.equal(result.memories[0]?.min, 1n);
  assert.equal(result.data[0]?.size, 19);
  assert.equal(result.start, 2);
  assert.equal(result.functionNames[2], "initialize");
});

void test("recognizes truncated WASM but rejects foreign signatures", async () => {
  assert.equal(await parseWasm(new File(["foreign"], "other")), null);
  const result = await parseWasm(new File([new Uint8Array([0, 97, 115, 109])], "short"));
  assert.match(result!.issues.join(" "), /header.*truncated/i);
});

void test("preserves sections and warns about invalid order, duplicates and truncation", async () => {
  const result = await parseWasm(wasmModule(wasmSection(3, [0]), wasmSection(1, [0]),
    wasmSection(1, [0]), [10, 100, 0]));
  assert.match(result!.issues.join(" "), /order/);
  assert.match(result!.issues.join(" "), /Duplicate/);
  assert.match(result!.issues.join(" "), /truncated/);
});

void test("routes WebAssembly through parseForUi, including truncated headers", async () => {
  assert.equal((await parseForUi(createWasmFile())).analyzer, "wasm");
  assert.equal((await parseForUi(new File([new Uint8Array([0, 97, 115, 109])], "short"))).analyzer, "wasm");
  assert.equal(await parseWasm(new File([], "empty")), null);
});

void test("warns for unsupported versions, invalid section sizes and unknown sections", async () => {
  const version = (await parseWasm(new File([new Uint8Array([0, 97, 115, 109, 13, 0, 1, 0])], "component")))!;
  assert.equal(version.version, 65549);
  assert.match(version.issues.join(" "), /Unsupported WebAssembly version/);
  const unknown = (await parseWasm(wasmModule(wasmSection(255, [1, 2]))))!;
  assert.match(unknown.issues.join(" "), /Unknown section 255/);
  assert.equal(unknown.sections[0]?.status, "opaque");
  assert.match((await parseWasm(wasmModule([1, 0xff, 0xff, 0xff, 0xff, 16])))!.issues.join(" "), /overflow/);
  assert.match((await parseWasm(wasmModule(wasmSection(1, [0, 1]))))!.issues.join(" "), /trailing/);
});

void test("never rejects any truncated prefix of a valid module", async () => {
  const bytes = new Uint8Array(await createWasmFile().arrayBuffer());
  await Promise.all(Array.from({ length: bytes.length + 1 }, (_, size) =>
    assert.doesNotReject(parseWasm(new File([bytes.subarray(0, size)], "truncated.wasm")))));
});

void test("does not impose a section-count cap", async () => {
  const sections = Array.from({ length: 10_001 }, () => wasmSection(0, [0]));
  const result = (await parseWasm(wasmModule(...sections)))!;
  assert.equal(result.sections.length, sections.length);
  assert.deepEqual(result.issues, []);
});

void test("streams a large data segment without reading whole sections into memory", async () => {
  const size = 9 * 1024 * 1024;
  const payloadHeader = [1, 1, ...wasmUnsigned(size)];
  class StreamingFile extends File {
    override arrayBuffer(): Promise<ArrayBuffer> { throw new Error("Whole-file read forbidden"); }
    override slice(): Blob { throw new Error("Sliced reads forbidden for sequential analysis"); }
  }
  const file = new StreamingFile([new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 11,
    ...wasmUnsigned(payloadHeader.length + size), ...payloadHeader]), new Uint8Array(size)], "large.wasm");
  const result = (await parseWasm(file))!;
  assert.deepEqual(result.issues, []);
  assert.equal(result.data[0]?.size, size);
  assert.equal(result.data[0]?.preview.length, 32);
});

void test("turns underlying stream failures and cancellation failures into issues", async () => {
  class BrokenFile extends File {
    override stream(): ReadableStream<Uint8Array<ArrayBuffer>> {
      return new ReadableStream({ start: controller => controller.error(new Error("read failure")) });
    }
  }
  const result = (await parseWasm(new BrokenFile(["12345678"], "broken")))!;
  assert.match(result.issues.join(" "), /read failure/);
  assert.match(result.issues.join(" "), /Stream cleanup/);
});

for (const name of ["lzma-sdk-decode/lzma-sdk-decode.wasm",
  "llvm-rust-demangle/llvm-rust-demangle.wasm", "llvm-aarch64-disasm/llvm-aarch64.wasm"]) {
  void test(`parses real shipped module ${name} against the engine oracle`, async () => {
    const bytes = readFileSync(new URL(import.meta.resolve(name)));
    assert.equal(WebAssembly.validate(bytes), true);
    const result = (await parseWasm(new File([bytes], name)))!;
    assert.deepEqual(result.issues, []);
    assert.equal(result.functions.length, result.code.length);
    assert.ok(result.code.length > 0);
  });
}

void test("the generated example executes its documented behavior", async () => {
  const bytes = await createWasmFile().arrayBuffer();
  const logs: number[] = [];
  const instantiated = await WebAssembly.instantiate(bytes, { env: { log: (value: number) => logs.push(value) } });
  const add = instantiated.instance.exports["add"] as (left: number, right: number) => number;
  assert.equal(add(20, 22), 42);
  assert.deepEqual(logs, [42]);
});

void test("preserves leading U+FEFF in export names exactly as the engine does", async () => {
  const file = wasmModule(wasmSection(1, [1, 0x60, 0, 0]), wasmSection(3, [1, 0]),
    wasmSection(7, [1, ...wasmString("\ufeffentry"), 0, 0]), wasmSection(10, [1, 2, 0, 0x0b]));
  const native = new WebAssembly.Module(await file.arrayBuffer());
  const parsed = (await parseWasm(file))!;
  assert.deepEqual(parsed.exports.map(entry => entry.name),
    WebAssembly.Module.exports(native).map(entry => entry.name));
  assert.deepEqual(parsed.issues, []);
});

void test("cancels and unlocks its input stream after an unsupported version", async () => {
  let cancelled = false;
  // Core header with unsupported version 2; no section decoder should run.
  const bytes = new Uint8Array([0, 97, 115, 109, 2, 0, 0, 0]);
  const stream = new ReadableStream<Uint8Array<ArrayBuffer>>({
    start: controller => controller.enqueue(bytes),
    cancel: () => { cancelled = true; }
  });
  class TrackedFile extends File {
    override stream(): ReadableStream<Uint8Array<ArrayBuffer>> { return stream; }
  }
  const result = (await parseWasm(new TrackedFile([bytes], "future.wasm")))!;
  assert.match(result.issues.join(" "), /Unsupported WebAssembly version 2/);
  assert.equal(cancelled, true);
  assert.equal(stream.locked, false);
});
