import assert from "node:assert/strict";
import { test } from "node:test";
import { readRuntimeFunctionChunks } from "../../../../../analyzers/pe/exception/runtime-function-chunks.js";
import { MockFile } from "../../../../helpers/mock-file.js";

for (const [entrySize, count, expected] of [[8, 8193, [65536, 8]], [12, 5462, [65532, 12]],
  [20, 3277, [65520, 20]], [8, 0, []]] as const) {
  void test(`runtime rows of ${entrySize} bytes are streamed in complete bounded chunks`, async () => {
    const issues: string[] = [];
    const lengths: number[] = [];
    for await (const view of readRuntimeFunctionChunks(new MockFile(new Uint8Array(entrySize * count)),
      count, entrySize, "truncated", issues)) lengths.push(view.byteLength);

    assert.deepEqual(lengths, expected);
    assert.deepEqual(issues, []);
  });
}

for (const count of [-1, 0.5, Infinity, NaN]) {
  void test(`runtime chunks reject invalid count ${count}`, async () => {
    const issues: string[] = [];
    const result = await Array.fromAsync(readRuntimeFunctionChunks(new MockFile(new Uint8Array(12)),
      count, 12, "truncated", issues));

    assert.deepEqual(result, []);
    assert.deepEqual(issues, ["RUNTIME_FUNCTION entry count is invalid."]);
  });
}

for (const entrySize of [-1, 0, 0.5, Infinity, NaN]) {
  void test(`runtime chunks reject invalid entry size ${entrySize}`, async () => {
    const issues: string[] = [];
    const result = await Array.fromAsync(readRuntimeFunctionChunks(new MockFile(new Uint8Array(12)),
      1, entrySize, "truncated", issues));

    assert.deepEqual(result, []);
    assert.deepEqual(issues, ["RUNTIME_FUNCTION entry size is invalid."]);
  });
}

void test("runtime chunks do not read incomplete rows from a known truncated extent", async context => {
  const source = new MockFile(new Uint8Array(11));
  const read = context.mock.method(source, "read");
  const issues: string[] = [];
  const result = await Array.fromAsync(readRuntimeFunctionChunks(source, 1, 12, "truncated", issues));

  assert.deepEqual(result, []);
  assert.equal(read.mock.callCount(), 0);
  assert.deepEqual(issues, ["truncated"]);
});

void test("runtime chunks stop on short physical reads and retain only whole rows", async context => {
  const source = new MockFile(new Uint8Array(65544));
  const read = context.mock.method(source, "read", async () => new DataView(source.data.buffer, 0, 12));
  const issues: string[] = [];
  const result = await Array.fromAsync(readRuntimeFunctionChunks(source, 8193, 8, "truncated", issues));

  assert.deepEqual(result.map(view => view.byteLength), [8]);
  assert.equal(read.mock.callCount(), 1);
  assert.deepEqual(issues, ["truncated"]);
});

void test("runtime chunks never expose excess bytes returned by an underlying reader", async context => {
  const source = new MockFile(new Uint8Array(16));
  context.mock.method(source, "read", async () => new DataView(source.data.buffer));
  const issues: string[] = [];
  const result = await Array.fromAsync(readRuntimeFunctionChunks(source, 1, 8, "truncated", issues));

  assert.deepEqual(result.map(view => view.byteLength), [8]);
  assert.deepEqual(issues, []);
});
