import assert from "node:assert/strict";
import { test } from "node:test";
import { createDisassembler } from "llvm-aarch64-disasm";
import { createAarch64SampleDecoder } from "../../../../analyzers/aarch64/sample-decoder.js";
import { aarch64Code } from "../../../fixtures/aarch64-code.js";

void test("privileged samples format once and retain register identity across cache hits", async () => {
  const decoder = await createDisassembler();
  let formatted = 0;
  let metadata = 0;
  const decode = createAarch64SampleDecoder({
    decode: (bytes, options) => { formatted++; return decoder.decode(bytes, options); },
    decodeMetadata: (bytes, options) => { metadata++; return decoder.decodeMetadata(bytes, options); }
  });
  // MRS X0,SCTLR_EL1; LLVM basic-a64-instructions.s and QEMU a64.decode.
  const bytes = aarch64Code([0xd5381000]).data;

  assert.deepEqual(decode(bytes, 0n).specialInstruction,
    { instruction: "MRS SCTLR_EL1", access: "EL1+" });
  assert.deepEqual(decode(bytes, 4n).specialInstruction,
    { instruction: "MRS SCTLR_EL1", access: "EL1+" });
  assert.equal(decode(bytes.subarray(0, 3), 8n).specialInstruction, undefined);
  assert.equal(formatted, 1);
  assert.equal(metadata, 1);
});

void test("special samples reject invalid decodes and preserve MSR and SYS operand labels", async () => {
  const decoder = await createDisassembler();
  const decode = createAarch64SampleDecoder(decoder);

  assert.equal(decode(aarch64Code([0xd5181001]).data, 0n).specialInstruction?.instruction,
    "MSR SCTLR_EL1");
  assert.equal(decode(aarch64Code([0xd508871f]).data, 0n).specialInstruction?.instruction,
    "TLBI VMALLE1");
  assert.equal(decode(aarch64Code([0xd4000022]).data, 0n).specialInstruction?.instruction, "HVC");
  assert.equal(createAarch64SampleDecoder({ decode: () => [{ status: "invalid", address: 0n,
    offset: 0, length: 0, bytesConsumed: 4 }] })(aarch64Code([0xd5381000]).data, 0n)
    .specialInstruction, undefined);
});

void test("generic system instructions keep operation encodings without register operands", async () => {
  const decode = createAarch64SampleDecoder(await createDisassembler());

  // Unaliased SYS/SYSL op1=0,C0,C0,op2=0, Rt=XZR (QEMU a64.decode).
  assert.equal(decode(aarch64Code([0xd508001f]).data, 0n).specialInstruction?.instruction,
    "SYS #0, C0, C0, #0");
  assert.equal(decode(aarch64Code([0xd528001f]).data, 0n).specialInstruction?.instruction,
    "SYSL #0, C0, C0, #0");
  assert.equal(decode(aarch64Code([0xd5034fdf]).data, 0n).specialInstruction?.instruction,
    "MSR DAIFSET");
  assert.equal(decode(aarch64Code([0xd5087620]).data, 0n).specialInstruction?.instruction,
    "DC IVAC");
  assert.equal(decode(aarch64Code([0xd508751f]).data, 0n).specialInstruction?.instruction,
    "IC IALLU");
  assert.equal(decode(aarch64Code([0xd5087800]).data, 0n).specialInstruction?.instruction,
    "AT S1E1R");
  assert.equal(decode(aarch64Code([0xd528001e]).data, 0n).specialInstruction?.instruction,
    "SYSL #0, C0, C0, #0");
});

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

void test("ISA sampling prefers metadata decoding and reuses cached requirements", () => {
  let calls = 0;
  const features = { source: "llvm-tablegen", scope: "opcode", known: true,
    predicates: [], nonAssemblerPredicates: [] } as const;
  const decode = createAarch64SampleDecoder({
    decode: () => { throw new Error("Full formatting must not run"); },
    decodeMetadata: () => {
      calls++;
      return [{ status: "success", address: 0n, length: 4, features,
        controlFlow: "unconditional-branch", target: 8n }];
    }
  });
  const bytes = aarch64Code([0x14000002]).data;

  assert.deepEqual(decode(bytes, 16n), { status: "success", address: 16n, length: 4,
    features, controlFlow: "unconditional-branch", target: 24n });
  assert.equal((decode(bytes, 32n) as { target: bigint }).target, 40n);
  assert.equal(calls, 1);
});
