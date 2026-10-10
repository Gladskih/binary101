import assert from "node:assert/strict";
import { test } from "node:test";
import { readPeNativeAotGc } from "../../../../analyzers/pe/native-aot-gc.js";
import { managedGcContainerFixture, failManagedGcReadAt } from "../../../helpers/managed-gc-container-fixture.js";
import { createNativeAotMetadataFixture } from "../../../helpers/pe-native-aot-metadata-fixture.js";

void test("binds NativeAOT GC maps to known managed runtime-function roots", async () => {
  const source = managedGcContainerFixture();
  const core = createNativeAotMetadataFixture().core;
  core.rvaToOff = source.mapper;
  core.dataDirs[3] = { name: "Exception", rva: 128, size: 24 };
  source.view.setUint32(128, 32, true);
  source.view.setUint32(136, 64, true);
  source.view.setUint32(140, 40, true); // Native code without managed metadata is not decoded.
  source.view.setUint32(148, 96, true);
  source.bytes[64] = 1;
  source.bytes.set(source.gc, 69);

  await readPeNativeAotGc(source.reader(), core, source.metadata);

  assert.equal(source.metadata.methodGcMaps?.methods.length, 1);
  assert.equal(source.metadata.methodGcMaps?.methods[0]?.startRva, 32);
  assert.equal(source.metadata.methodGcMaps?.methods[0]?.info.header.codeLength, 32);
  assert.deepEqual(source.metadata.methodGcMaps?.warnings, []);
});

void test("keeps malformed GC warnings visible and ignores unsupported architectures", async () => {
  const source = managedGcContainerFixture();
  const core = createNativeAotMetadataFixture().core;
  core.rvaToOff = source.mapper;
  core.dataDirs[3] = { name: "Exception", rva: 128, size: 13 };
  source.view.setUint32(128, 32, true);
  source.view.setUint32(136, 255, true);

  await readPeNativeAotGc(source.reader(), core, source.metadata);

  assert.match(source.metadata.methodGcMaps?.warnings.join() ?? "", /truncated/);
  delete source.metadata.methodGcMaps;
  core.coff.Machine = 0x14c;
  await readPeNativeAotGc(source.reader(), core, source.metadata);
  assert.equal(source.metadata.methodGcMaps, undefined);
});

void test("skips funclets and empty GC payloads and reports directory I/O failures", async () => {
  const source = managedGcContainerFixture();
  const core = createNativeAotMetadataFixture().core;
  core.rvaToOff = source.mapper;
  core.dataDirs[3] = { name: "Exception", rva: 128, size: 12 };
  source.view.setUint32(128, 32, true);
  source.view.setUint32(136, 64, true);
  source.bytes.set([1, 0, 0, 0, 1], 64);
  await readPeNativeAotGc(source.reader(), core, source.metadata);
  assert.deepEqual(source.metadata.methodGcMaps?.methods, []);
  source.bytes[68] = 0;
  await readPeNativeAotGc(source.reader(), core, source.metadata);
  assert.match(source.metadata.methodGcMaps?.warnings.join() ?? "", /zero code length/);
  const reader = source.reader();
  reader.read = async () => { throw new Error("disk failed"); };
  await readPeNativeAotGc(reader, core, source.metadata);
  assert.match(source.metadata.methodGcMaps?.warnings.join() ?? "", /disk failed/);
  reader.read = async () => { throw "untyped disk failed"; };
  await readPeNativeAotGc(reader, core, source.metadata);
  assert.match(source.metadata.methodGcMaps?.warnings.join() ?? "", /untyped disk failed/);
  core.dataDirs = [];
  await readPeNativeAotGc(reader, core, source.metadata);
  delete source.metadata.stackTraceMap;
  core.dataDirs[3] = { name: "Exception", rva: 128, size: 12 };
  source.metadata.majorVersion = 10;
  await readPeNativeAotGc(source.reader(), core, source.metadata);
  assert.deepEqual(source.metadata.methodGcMaps?.methods, []);
});

void test("reports untyped method-specific I/O failures", async () => {
  const source = managedGcContainerFixture();
  const core = createNativeAotMetadataFixture().core;
  core.rvaToOff = source.mapper;
  core.dataDirs[3] = { name: "Exception", rva: 128, size: 12 };
  source.view.setUint32(128, 32, true);
  source.view.setUint32(136, 64, true);
  const reader = failManagedGcReadAt(source.reader(), 64, "method read failed");

  await readPeNativeAotGc(reader, core, source.metadata);

  assert.match(source.metadata.methodGcMaps?.warnings.join() ?? "", /method read failed/);
});
