import assert from "node:assert/strict";
import { test } from "node:test";
import { readPeNativeAotGc } from "../../../../analyzers/pe/native-aot-gc.js";
import { managedGcContainerFixture, failManagedGcReadAt } from "../../../helpers/managed-gc-container-fixture.js";
import { createNativeAotMetadataFixture } from "../../../helpers/pe-native-aot-metadata-fixture.js";

void test("binds NativeAOT GC maps to known managed runtime-function roots", async () => {
  const source = managedGcContainerFixture();
  const core = createNativeAotMetadataFixture().core;
  core.rvaToOff = source.mapper;
  // PE data-directory index 3 is the Exception Table.
  // https://learn.microsoft.com/windows/win32/debug/pe-format#optional-header-data-directories-image-only
  const { exceptionDirectoryRva, methodRva, nativeOnlyMethodRva, rootUnwindRva,
    rootGcInfoRva, runtimeFunctionBytes } = source.layout;
  core.dataDirs[3] = { name: "Exception", rva: exceptionDirectoryRva,
    size: runtimeFunctionBytes * 2 };
  source.view.setUint32(exceptionDirectoryRva, methodRva, true);
  source.view.setUint32(exceptionDirectoryRva + 8, rootUnwindRva, true);
  source.view.setUint32(exceptionDirectoryRva + runtimeFunctionBytes, nativeOnlyMethodRva, true);
  source.view.setUint32(exceptionDirectoryRva + runtimeFunctionBytes + 8, rootUnwindRva, true);
  source.bytes[rootUnwindRva] = 1;
  source.bytes.set(source.gc, rootGcInfoRva);

  await readPeNativeAotGc(source.reader(), core, source.metadata);

  assert.equal(source.metadata.methodGcMaps?.methods.length, 1);
  assert.equal(source.metadata.methodGcMaps?.methods[0]?.startRva, methodRva);
  assert.equal(source.metadata.methodGcMaps?.methods[0]?.info.header.codeLength,
    source.layout.codeLength);
  assert.deepEqual(source.metadata.methodGcMaps?.warnings, []);
});

void test("keeps malformed GC warnings visible and ignores unsupported architectures", async () => {
  const source = managedGcContainerFixture();
  const core = createNativeAotMetadataFixture().core;
  core.rvaToOff = source.mapper;
  const { exceptionDirectoryRva, methodRva, runtimeFunctionBytes } = source.layout;
  core.dataDirs[3] = { name: "Exception", rva: exceptionDirectoryRva,
    size: runtimeFunctionBytes + 1 };
  source.view.setUint32(exceptionDirectoryRva, methodRva, true);
  source.view.setUint32(exceptionDirectoryRva + 8, source.bytes.length - 1, true);

  await readPeNativeAotGc(source.reader(), core, source.metadata);

  assert.match(source.metadata.methodGcMaps?.warnings.join() ?? "", /truncated/);
  delete source.metadata.methodGcMaps;
  // IMAGE_FILE_MACHINE_I386 is unsupported by the AMD64 GC path.
  // https://learn.microsoft.com/windows/win32/debug/pe-format#machine-types
  core.coff.Machine = 0x14c;
  await readPeNativeAotGc(source.reader(), core, source.metadata);
  assert.equal(source.metadata.methodGcMaps, undefined);
});

void test("skips funclets and empty GC payloads and reports directory I/O failures", async () => {
  const source = managedGcContainerFixture();
  const core = createNativeAotMetadataFixture().core;
  core.rvaToOff = source.mapper;
  const { exceptionDirectoryRva, methodRva, rootUnwindRva, runtimeFunctionBytes } = source.layout;
  core.dataDirs[3] = { name: "Exception", rva: exceptionDirectoryRva,
    size: runtimeFunctionBytes };
  source.view.setUint32(exceptionDirectoryRva, methodRva, true);
  source.view.setUint32(exceptionDirectoryRva + 8, rootUnwindRva, true);
  source.bytes.set([1, 0, 0, 0, 1], rootUnwindRva);
  await readPeNativeAotGc(source.reader(), core, source.metadata);
  assert.deepEqual(source.metadata.methodGcMaps?.methods, []);
  source.bytes[rootUnwindRva + 4] = 0;
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
  core.dataDirs[3] = { name: "Exception", rva: exceptionDirectoryRva,
    size: runtimeFunctionBytes };
  source.view.setUint32(exceptionDirectoryRva, methodRva, true);
  source.view.setUint32(exceptionDirectoryRva + 8, rootUnwindRva, true);
  source.metadata.majorVersion = 10;
  await readPeNativeAotGc(source.reader(), core, source.metadata);
  assert.deepEqual(source.metadata.methodGcMaps?.methods, []);
});

void test("reports untyped method-specific I/O failures", async () => {
  const source = managedGcContainerFixture();
  const core = createNativeAotMetadataFixture().core;
  core.rvaToOff = source.mapper;
  const { exceptionDirectoryRva, methodRva, rootUnwindRva, runtimeFunctionBytes } = source.layout;
  core.dataDirs[3] = { name: "Exception", rva: exceptionDirectoryRva,
    size: runtimeFunctionBytes };
  source.view.setUint32(exceptionDirectoryRva, methodRva, true);
  source.view.setUint32(exceptionDirectoryRva + 8, rootUnwindRva, true);
  const reader = failManagedGcReadAt(source.reader(), rootUnwindRva, "method read failed");

  await readPeNativeAotGc(reader, core, source.metadata);

  assert.match(source.metadata.methodGcMaps?.warnings.join() ?? "", /method read failed/);
});
