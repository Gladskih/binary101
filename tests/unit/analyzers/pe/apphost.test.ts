"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeAppHost } from "../../../../analyzers/pe/apphost/index.js";
import { parsePe } from "../../../../analyzers/pe/index.js";
import {
  appHostFixtureRva,
  createPeAppHostFixture,
  createIntegratedPeAppHostFile,
  refreshPeAppHostFixture,
  writeBundleHeader
} from "../../../fixtures/pe-apphost-fixture.js";

void test("analyzePeAppHost finds a bound non-bundle apphost", async () => {
  const fixture = createPeAppHostFixture();

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.deepEqual(result, {
    locators: [{ rva: appHostFixtureRva(0x148), bundleHeaderOffset: 0n }],
    bindings: [{ rva: appHostFixtureRva(0x280), kind: "managed-assembly", value: "Fixture.dll" }],
    issues: []
  });
});

void test("analyzePeAppHost parses the fixed single-file bundle header", async () => {
  const fixture = createPeAppHostFixture(0x800n);
  writeBundleHeader(fixture, 0x800);

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.deepEqual(result?.locators[0]?.bundleHeader, {
    majorVersion: 6,
    minorVersion: 0,
    embeddedFileCount: 3,
    bundleId: "fixture-id",
    depsJson: { offset: 0x700n, size: 0x20n },
    runtimeConfigJson: { offset: 0x720n, size: 0x30n },
    flags: 1n
  });
  assert.deepEqual(result?.issues, []);
});

void test("analyzePeAppHost reports an out-of-file bundle header", async () => {
  const fixture = createPeAppHostFixture(0x2000n);

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.equal(result?.locators[0]?.bundleHeader, undefined);
  assert.ok(result?.issues.some(issue => issue.includes("outside the file")));
});

void test("analyzePeAppHost recognizes an unbound SDK template", async () => {
  const placeholder = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";
  const fixture = createPeAppHostFixture(0n, placeholder);

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.deepEqual(result?.bindings, [{
    rva: appHostFixtureRva(0x280),
    kind: "unbound-placeholder",
    value: placeholder
  }]);
});

void test("analyzePeAppHost accepts case-insensitive managed assembly suffixes", async () => {
  const fixture = createPeAppHostFixture(0n, "Fixture.DLL");

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.equal(result?.bindings[0]?.value, "Fixture.DLL");
});

void test("analyzePeAppHost reports multiple locators and bindings", async () => {
  const fixture = createPeAppHostFixture();
  fixture.bytes.copyWithin(0x200, 0x148, 0x170);
  fixture.bytes.set(new TextEncoder().encode("Second.dll\0"), 0x380);
  refreshPeAppHostFixture(fixture);

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.equal(result?.locators.length, 2);
  assert.deepEqual(result?.bindings.map(binding => binding.value), ["Fixture.dll", "Second.dll"]);
  assert.ok(result?.issues.some(issue => issue.startsWith("Multiple .NET apphost")));
  assert.ok(result?.issues.some(issue => issue.startsWith("Multiple embedded managed")));
});

void test("analyzePeAppHost rejects invalid UTF-8 managed bindings", async () => {
  const fixture = createPeAppHostFixture();
  fixture.bytes[0x280] = 0xff;
  refreshPeAppHostFixture(fixture);

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.deepEqual(result?.bindings, []);
  assert.ok(result?.issues.some(issue => issue.includes("application path was not found")));
});

void test("analyzePeAppHost reports short locator reads", async () => {
  const fixture = createPeAppHostFixture();
  const empty = new DataView(new ArrayBuffer(0));
  const reader = {
    ...fixture.reader,
    read: async (offset: number, size: number) =>
      offset === 0x148 ? empty : fixture.reader.read(offset, size)
  };

  const result = await analyzePeAppHost(fixture.file, reader, [fixture.section]);

  assert.equal(result?.locators[0]?.bundleHeaderOffset, null);
  assert.ok(result?.issues.some(issue => issue.includes("locator is truncated")));
});

void test("analyzePeAppHost reports short binding reads", async () => {
  const fixture = createPeAppHostFixture();
  const reader = {
    ...fixture.reader,
    readBytes: async (offset: number, size: number) =>
      offset === 0x100 && size > 0x100
        ? new Uint8Array(0)
        : fixture.reader.readBytes(offset, size)
  };

  const result = await analyzePeAppHost(fixture.file, reader, [fixture.section]);

  assert.deepEqual(result?.bindings, []);
  assert.ok(result?.issues.some(issue => issue.includes("application path was not found")));
});

void test("analyzePeAppHost ignores signatures outside writable initialized data", async () => {
  const fixture = createPeAppHostFixture();
  fixture.section.characteristics = 0x40000040;

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.equal(result, null);
});

void test("analyzePeAppHost ignores sections starting outside the file", async () => {
  const fixture = createPeAppHostFixture();
  fixture.section.pointerToRawData = fixture.file.size;

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.equal(result, null);
});

void test("analyzePeAppHost falls back to raw size when virtual size is zero", async () => {
  const fixture = createPeAppHostFixture();
  fixture.section.virtualSize = 0;

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.equal(result?.bindings[0]?.value, "Fixture.dll");
});

void test("analyzePeAppHost reports a marker truncated at its section boundary", async () => {
  const fixture = createPeAppHostFixture();
  fixture.section.pointerToRawData = 0x150;
  fixture.section.virtualAddress = 0x2050;
  fixture.section.sizeOfRawData -= 0x50;
  fixture.section.virtualSize -= 0x50;

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.equal(result?.locators[0]?.bundleHeaderOffset, null);
  assert.ok(result?.issues.some(issue => issue.includes("precedes its containing section")));
});

void test("analyzePeAppHost returns null without the full marker signature", async () => {
  const fixture = createPeAppHostFixture();
  fixture.bytes[0x150] = fixture.bytes[0x150]! ^ 0xff;
  refreshPeAppHostFixture(fixture);

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.equal(result, null);
});

void test("parsePe integrates apphost metadata and subtype detection", async () => {
  const result = await parsePe(createIntegratedPeAppHostFile());

  assert.equal(result?.subtype, "dotnet-apphost");
  assert.equal(result && "appHost" in result ? result.appHost?.bindings[0]?.value : null,
    "Integrated.dll");
});

void test("analyzePeAppHost finds a binding in a separate writable section", async () => {
  const fixture = createPeAppHostFixture();
  const split = 0x200;
  const sections = [
    { ...fixture.section, sizeOfRawData: split - fixture.section.pointerToRawData,
      virtualSize: split - fixture.section.pointerToRawData },
    { ...fixture.section, pointerToRawData: split, virtualAddress: appHostFixtureRva(split),
      sizeOfRawData: 0x500, virtualSize: 0x500 }
  ];

  const result = await analyzePeAppHost(fixture.file, fixture.reader, sections);

  assert.equal(result?.bindings[0]?.value, "Fixture.dll");
});

void test("analyzePeAppHost streams each section only once", async () => {
  const fixture = createPeAppHostFixture();
  const slice = fixture.file.slice.bind(fixture.file);
  let streams = 0;
  fixture.file.slice = (start, end) => {
    if (start === fixture.section.pointerToRawData &&
      end === start + fixture.section.sizeOfRawData) streams += 1;
    return slice(start, end);
  };

  await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.equal(streams, 1);
});

void test("analyzePeAppHost accepts the maximum apphost binding length", async () => {
  // EMBED_MAX permits 1024 UTF-8 bytes plus NUL in dotnet/runtime apphost/apphost.c.
  const path = `${"a".repeat(1020)}.dll`;
  const fixture = createPeAppHostFixture(0n, path);

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.equal(result?.bindings[0]?.value, path);
});

void test("analyzePeAppHost reuses a bundle header referenced by duplicate locators", async () => {
  const fixture = createPeAppHostFixture(0x800n);
  fixture.bytes.copyWithin(0x200, 0x148, 0x170);
  writeBundleHeader(fixture, 0x800);
  let headerReads = 0;
  const reader = { ...fixture.reader, read: async (offset: number, size: number) => {
    if (offset === 0x800) headerReads += 1;
    return fixture.reader.read(offset, size);
  } };

  const result = await analyzePeAppHost(fixture.file, reader, [fixture.section]);

  assert.equal(result?.locators.length, 2);
  // One bounded prefix read and one variable-header read, independent of locator count.
  assert.equal(headerReads, 2);
});

void test("analyzePeAppHost requires initialized data even in a writable section", async () => {
  const fixture = createPeAppHostFixture();
  // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE without IMAGE_SCN_CNT_INITIALIZED_DATA.
  fixture.section.characteristics = 0xc0000000;

  assert.equal(await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]), null);
});

for (const offset of [-1n, 0x1000n, 0x20000000000000n]) {
  void test(`analyzePeAppHost preserves invalid locator offset ${offset}`, async () => {
    const fixture = createPeAppHostFixture(offset);

    const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

    assert.equal(result?.locators[0]?.bundleHeaderOffset, offset);
    assert.equal(result?.locators[0]?.bundleHeader, undefined);
    assert.match(result?.issues.join(" ") ?? "", /outside the file/);
  });
}

for (const path of ["control\u0001.dll", `${"a".repeat(1021)}.dll`]) {
  void test(`analyzePeAppHost rejects an invalid binding of ${path.length} bytes`, async () => {
    const fixture = createPeAppHostFixture(0n, path);

    const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

    assert.deepEqual(result?.bindings, []);
    assert.match(result?.issues.join(" ") ?? "", /application path was not found/);
  });
}

void test("analyzePeAppHost preserves spaces in a binding", async () => {
  const fixture = createPeAppHostFixture(0n, "An app.dll");

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.equal(result?.bindings[0]?.value, "An app.dll");
});

void test("analyzePeAppHost accepts a locator starting exactly at a section boundary", async () => {
  const fixture = createPeAppHostFixture();
  fixture.section.pointerToRawData = 0x148;
  fixture.section.virtualAddress = appHostFixtureRva(0x148);

  const result = await analyzePeAppHost(fixture.file, fixture.reader, [fixture.section]);

  assert.deepEqual(result?.locators, [{ rva: appHostFixtureRva(0x148), bundleHeaderOffset: 0n }]);
  assert.deepEqual(result?.issues, []);
});
