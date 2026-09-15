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

void test("colliding words replace one slot and empty decoder output remains an explicit error", () => {
  let calls = 0;
  const decode = createAarch64SampleDecoder({ decode: () => {
    calls++;
    return [{ status: "invalid", address: 0n, offset: 0, length: 0, bytesConsumed: 4 }];
  } });
  // 0 and 112044 collide under the multiplicative hash's high 16 bits.
  decode(aarch64Code([0]).data, 0n);
  decode(aarch64Code([112044]).data, 0n);
  decode(aarch64Code([0]).data, 0n);
  decode(aarch64Code([0]).data, 0n);

  assert.equal(calls, 3);
  assert.throws(() => createAarch64SampleDecoder({ decode: () => [] })(new Uint8Array(4), 0n),
    /returned no instruction/);
});

void test("hot words survive more than 4096 distinct decodes without a whole-cache flush", () => {
  let calls = 0;
  const decode = createAarch64SampleDecoder({ decode: () => {
    calls++;
    return [{ status: "invalid", address: 0n, offset: 0, length: 0, bytesConsumed: 4 }];
  } });
  const hot = aarch64Code([0]).data;

  decode(hot, 0n);
  Array.from({ length: 4097 }, (_, index) => {
    decode(aarch64Code([index + 1]).data, 0n);
    decode(hot, 0n);
  });

  assert.equal(calls, 4098);
});
