import assert from "node:assert/strict";
import { test } from "node:test";
import { createDisassembler } from "llvm-aarch64-disasm";
import { createAarch64SampleDecoder } from "../../../../analyzers/aarch64/sample-decoder.js";
import { aarch64Code } from "../../../fixtures/aarch64-code.js";

void test("cached A64 words relocate forward and backward branches at every address", async () => {
  const decoder = await createDisassembler();
  let calls = 0;
  const decode = createAarch64SampleDecoder({ decode: (bytes, options) => {
    calls++;
    return decoder.decode(bytes, options);
  } });
  // A64 B immediate uses a signed PC-relative offset (LLVM MC branch analysis).
  const forward = aarch64Code([0x14000002]).data;
  const backward = aarch64Code([0x17ffffff]).data;

  assert.equal((decode(forward, 0x1000n) as { target: bigint }).target, 0x1008n);
  assert.equal((decode(forward, 0x2000n) as { target: bigint }).target, 0x2008n);
  assert.equal((decode(backward, 0n) as { target: bigint }).target, 0xfffffffffffffffen - 2n);
  assert.equal((decode(backward, 8n) as { target: bigint }).target, 4n);
  assert.equal((decode(forward, 16n) as { target: bigint }).target, 24n);
  assert.equal(calls, 2);
  assert.equal(decode(forward.subarray(0, 2), 0n).status, "invalid");
  assert.equal(decode(aarch64Code([0xd65f03c0]).data, 0n).status, "success");
});

void test("word cache is bounded and empty decoder output remains an explicit error", () => {
  let calls = 0;
  const decode = createAarch64SampleDecoder({ decode: () => {
    calls++;
    return [{ status: "invalid", address: 0n, offset: 0, length: 0, bytesConsumed: 4 }];
  } });
  // Exceed the bounded 4096-word cache, then request its oldest word again.
  Array.from({ length: 4097 }, (_, word) => decode(aarch64Code([word]).data, 0n));
  decode(aarch64Code([0]).data, 0n);

  assert.equal(calls, 4098);
  assert.throws(() => createAarch64SampleDecoder({ decode: () => [] })(new Uint8Array(4), 0n),
    /returned no instruction/);
});
