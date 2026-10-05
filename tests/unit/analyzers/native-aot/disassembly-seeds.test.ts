import assert from "node:assert/strict";
import test from "node:test";
import { collectNativeAotMapSeeds } from "../../../../analyzers/native-aot/disassembly-seeds.js";
import { createNativeAotInitializerFixture } from "../../../helpers/native-aot-initializer-fixture.js";
import { createNativeAotInvokeFixture } from "../../../helpers/native-aot-invoke-fixture.js";
import { parseNativeAotInvokeMap } from "../../../../analyzers/native-aot/invoke-map.js";

void test("NativeAOT seed groups retain unique method and invoke stub addresses", async () => {
  const fixture = createNativeAotInvokeFixture();
  const map = (await parseNativeAotInvokeMap(fixture.image, fixture.sections))!;
  map.entries.push({ ...map.entries[0]! });
  const metadata = { ...createNativeAotInitializerFixture().header, invokeMap: map };

  assert.deepEqual(collectNativeAotMapSeeds(metadata), [
    { source: "NativeAOT invoke methods", rvas: [fixture.codeRvas[0]] },
    { source: "NativeAOT invoke stubs", rvas: [fixture.codeRvas[1]] }
  ]);
});

void test("NativeAOT omits absent maps and unresolved code addresses", async () => {
  const fixture = createNativeAotInvokeFixture();
  fixture.sections.pop();
  const metadata = createNativeAotInitializerFixture().header;
  const map = (await parseNativeAotInvokeMap(fixture.image, fixture.sections))!;

  assert.deepEqual(collectNativeAotMapSeeds(metadata), []);
  assert.deepEqual(collectNativeAotMapSeeds({ ...metadata, invokeMap: map }), []);
});

void test("NativeAOT stack-trace roots are unique and include hidden methods", () => {
  const metadata = { ...createNativeAotInitializerFixture().header, stackTraceMap: { entries: [
    { command: 0x10, methodRva: 16 }, { command: 0, methodRva: 16 }, { command: 0, methodRva: null }
  ], warnings: [] } };

  assert.deepEqual(collectNativeAotMapSeeds(metadata), [
    { source: "NativeAOT stack-trace methods", rvas: [16] }
  ]);
});
