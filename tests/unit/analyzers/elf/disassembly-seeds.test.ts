import assert from "node:assert/strict";
import test from "node:test";
import { collectElfDisassemblySeedGroups } from "../../../../analyzers/elf/disassembly-seeds.js";
import type { ElfProgramHeader } from "../../../../analyzers/elf/types.js";
import { createNativeAotInitializerFixture } from "../../../helpers/native-aot-initializer-fixture.js";
import { createNativeAotInvokeFixture } from "../../../helpers/native-aot-invoke-fixture.js";
import { createNativeAotStackTraceFixture } from "../../../helpers/native-aot-stack-trace-fixture.js";
import { parseNativeAotInvokeMap } from "../../../../analyzers/native-aot/invoke-map.js";
import { parseNativeAotStackTraceMap } from "../../../../analyzers/native-aot/stack-trace-map.js";

void test("ELF seeds reuse NativeAOT maps and add the full-width image base to their RVAs", async context => {
  const invoke = createNativeAotInvokeFixture();
  const stack = createNativeAotStackTraceFixture();
  const file = new File([], "aot-elf");
  const read = context.mock.method(file, "slice");
  // Exercise an ELF image base above the JavaScript exact integer range.
  const imageBase = 0x20000000000001n;
  const programHeaders: ElfProgramHeader[] = [{ type: 1, typeName: "LOAD", flags: 5,
    flagNames: [], index: 0, offset: 0n,
    vaddr: imageBase, paddr: imageBase, filesz: 0n, memsz: 0n, align: 1n }];
  const nativeAot = { ...createNativeAotInitializerFixture().header,
    invokeMap: (await parseNativeAotInvokeMap(invoke.image, invoke.sections))!,
    stackTraceMap: (await parseNativeAotStackTraceMap(stack.image, [stack.section]))! };

  const groups = await collectElfDisassemblySeedGroups({ file, programHeaders, sections: [],
    is64: true, littleEndian: true, issues: [], nativeAot });

  assert.deepEqual(groups, [
    { source: "NativeAOT invoke methods", vaddrs: [imageBase + BigInt(invoke.codeRvas[0]!)] },
    { source: "NativeAOT invoke stubs", vaddrs: [imageBase + BigInt(invoke.codeRvas[1]!)] },
    { source: "NativeAOT stack-trace methods", vaddrs: stack.codeRvas.map(rva => imageBase + BigInt(rva)) }
  ]);
  assert.equal(read.mock.callCount(), 0);
});

void test("ELF omits NativeAOT seeds when the image has no load base", async () => {
  const nativeAot = { ...createNativeAotInitializerFixture().header,
    stackTraceMap: { entries: [{ command: 0, methodRva: 16 }], warnings: [] } };

  const groups = await collectElfDisassemblySeedGroups({ file: new File([], "unmapped"),
    programHeaders: [], sections: [], is64: true, littleEndian: true, issues: [], nativeAot });

  assert.deepEqual(groups, []);
});
