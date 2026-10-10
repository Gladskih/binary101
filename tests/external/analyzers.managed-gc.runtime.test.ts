import assert from "node:assert/strict";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import { test } from "node:test";

const lines = (path: string) => createInterface({ input: createReadStream(path), crlfDelay: Infinity });

// Generate prefix-input.txt/prefix-expected.jsonl with managed-gc-reference-capture.ts.
// Feed v3/v4 input records to the matching C++ executable and save their JSON lines as
// prefix-actual3.jsonl / prefix-actual4.jsonl. The C++ tool links unmodified runtime sources.
void test("matches runtime C++ GC decoding and liveness at every interruptible code offset", {
  skip: !process.env["BINARY101_MANAGED_GC_REFERENCE"]
}, async () => {
  const prefix = process.env["BINARY101_MANAGED_GC_REFERENCE"]!;
  const inputs = lines(`${prefix}-input.txt`)[Symbol.asyncIterator]();
  const versions = { 3: lines(`${prefix}-actual3.jsonl`)[Symbol.asyncIterator](),
    4: lines(`${prefix}-actual4.jsonl`)[Symbol.asyncIterator]() };
  let methods = 0;
  for await (const expected of lines(`${prefix}-expected.jsonl`)) {
    const input = await inputs.next();
    assert.equal(input.done, false);
    const version = Number(input.value![0]);
    assert.ok(version === 3 || version === 4);
    const actual = await versions[version].next();
    assert.equal(actual.done, false);
    assert.deepEqual(JSON.parse(actual.value!), JSON.parse(expected), `GC payload ${methods++}`);
  }
  assert.ok(methods > 0);
  assert.equal((await inputs.next()).done, true);
  assert.equal((await versions[3].next()).done, true);
  assert.equal((await versions[4].next()).done, true);
});
