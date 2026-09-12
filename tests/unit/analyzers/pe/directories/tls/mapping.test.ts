"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../../../../../analyzers/pe/index.js";
import { createTlsMappingFixture } from "../../../../../fixtures/pe-tls-mapping.js";
import { createPeWithPartialTlsCallback } from "../../../../../fixtures/pe-tls-file.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

void test("PE analysis excludes a partial callback using the real section RVA mapper", async () => {
  const parsed = expectDefined(await parsePe(createPeWithPartialTlsCallback()));

  assert.ok(isPeWindowsParseResult(parsed));
  assert.deepEqual(parsed.tls?.CallbackRvas, [0x1100]);
  assert.equal(parsed.tls?.CallbackCount, 1);
  assert.equal(parsed.tls?.callbackTableStatus, "incomplete");
  assert.deepEqual(parsed.tls?.warnings,
    ["TLS callback table is truncated or unmapped before the null terminator."]);
});

for (const pointerSize of [4, 8] as const) {
  void test(`TLS ${pointerSize}: joins callback bytes across discontiguous file ranges`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    // Split after two bytes so the physical and virtual DWORD values differ.
    fixture.view.setUint16(fixture.tableRva, 0x5678, true);
    fixture.view.setUint16(0x100, 0x1234, true);

    const tls = expectDefined(await fixture.parse(rva =>
      rva >= fixture.tableRva + 2 ? 0x100 + rva - fixture.tableRva - 2 : rva
    ));

    assert.deepEqual(tls.CallbackRvas, [0x12345678]);
    assert.equal(tls.callbackTableStatus, "complete");
    assert.equal(tls.warnings, undefined);
  });

  void test(`TLS ${pointerSize}: rejects a callback with an unmapped interior byte`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    fixture.writePointer(fixture.tableRva, 0x5678n);

    const tls = expectDefined(await fixture.parse(rva =>
      rva === fixture.tableRva + 1 ? null : rva
    ));

    assert.deepEqual(tls.CallbackRvas, []);
    assert.equal(tls.callbackTableStatus, "incomplete");
    assert.match(tls.warnings?.join(" ") ?? "", /truncated or unmapped/);
  });

  void test(`TLS ${pointerSize}: preserves earlier callbacks when a later slot is partial`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    fixture.writePointer(fixture.tableRva, 0x5678n);
    fixture.writePointer(fixture.tableRva + pointerSize, 0x1234n);

    const tls = expectDefined(await fixture.parse(rva =>
      rva === fixture.tableRva + pointerSize + 1 ? null : rva
    ));

    assert.deepEqual(tls.CallbackRvas, [0x5678]);
    assert.equal(tls.CallbackCount, 1);
    assert.equal(tls.callbackTableStatus, "incomplete");
  });

  void test(`TLS ${pointerSize}: does not wrap the next callback RVA to zero`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    // PE RVAs are DWORDs; this is the last complete pointer in the address space.
    const lastPointerRva = 0x100000000 - pointerSize;
    fixture.writePointer(fixture.headerRva + pointerSize * 3, BigInt(lastPointerRva));
    fixture.writePointer(fixture.tableRva, 0x5678n);
    const visited: number[] = [];

    const tls = expectDefined(await fixture.parse(rva => {
      visited.push(rva);
      return rva >= lastPointerRva ? fixture.tableRva + rva - lastPointerRva : rva;
    }));

    assert.deepEqual(tls.CallbackRvas, [0x5678]);
    assert.equal(tls.callbackTableStatus, "incomplete");
    assert.match(tls.warnings?.join(" ") ?? "", /RVA.*range/);
    assert.ok(!visited.includes(0));
  });

  void test(`TLS ${pointerSize}: rejects a pointer crossing the RVA limit`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    fixture.writePointer(fixture.headerRva + pointerSize * 3, 0xffffffffn);
    fixture.writePointer(fixture.tableRva, 0x5678n);

    const tls = expectDefined(await fixture.parse(rva =>
      rva === 0xffffffff ? fixture.tableRva : rva
    ));

    assert.deepEqual(tls.CallbackRvas, []);
    assert.equal(tls.callbackTableStatus, "incomplete");
    assert.match(tls.warnings?.join(" ") ?? "", /RVA.*range/);
  });

  void test(`TLS ${pointerSize}: reads a header split across file ranges`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    fixture.bytes.set(fixture.bytes.slice(fixture.headerRva + pointerSize,
      fixture.headerRva + fixture.headerSize), 0x100);
    fixture.bytes.fill(0, fixture.headerRva + pointerSize, fixture.headerRva + fixture.headerSize);
    fixture.writePointer(fixture.tableRva, 0x5678n);

    const tls = expectDefined(await fixture.parse(rva =>
      rva >= fixture.headerRva + pointerSize && rva < fixture.headerRva + fixture.headerSize
        ? 0x100 + rva - fixture.headerRva - pointerSize : rva
    ));

    assert.equal(tls.AddressOfIndex, BigInt(fixture.section.virtualAddress));
    assert.deepEqual(tls.CallbackRvas, [0x5678]);
    assert.equal(tls.warnings, undefined);
  });

  void test(`TLS ${pointerSize}: rejects a header with an unmapped final byte`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);

    const tls = expectDefined(await fixture.parse(rva =>
      rva === fixture.headerRva + fixture.headerSize - 1 ? null : rva
    ));

    assert.equal(tls.parsed, false);
    assert.deepEqual(tls.warnings, [
      `TLS directory is truncated or unmapped before the full ${pointerSize * 8}-bit header could be read.`
    ]);
  });

  void test(`TLS ${pointerSize}: marks a terminated empty table complete`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);

    const tls = expectDefined(await fixture.parse());

    assert.deepEqual(tls.CallbackRvas, []);
    assert.equal(tls.callbackTableStatus, "complete");
    assert.equal(tls.warnings, undefined);
  });

  void test(`TLS ${pointerSize}: distinguishes an absent callback table`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    fixture.writePointer(fixture.headerRva + pointerSize * 3, 0n);

    const tls = expectDefined(await fixture.parse());

    assert.equal(tls.callbackTableStatus, "absent");
    assert.equal(tls.warnings, undefined);
  });

  void test(`TLS ${pointerSize}: warns when the index section is smaller than a DWORD`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    fixture.section.virtualSize = 1;

    const tls = expectDefined(await fixture.parse());

    assert.match(tls.warnings?.join(" ") ?? "", /AddressOfIndex/);
  });

  void test(`TLS ${pointerSize}: warns for a zero RVA with a nonzero directory size`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    expectDefined(fixture.directories[0]).rva = 0;

    const tls = expectDefined(await fixture.parse());

    assert.equal(tls.parsed, false);
    assert.deepEqual(tls.warnings, ["TLS directory has a non-zero size but RVA is 0."]);
  });

  void test(`TLS ${pointerSize}: treats a zero directory as absent`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    fixture.directories.splice(0, 1, { name: "TLS", rva: 0, size: 0 });

    assert.equal(await fixture.parse(), null);
  });

  void test(`TLS ${pointerSize}: preserves a nonzero RVA with zero directory size`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    expectDefined(fixture.directories[0]).size = 0;

    const tls = expectDefined(await fixture.parse());

    assert.equal(tls.parsed, false);
    assert.deepEqual(tls.warnings, [
      `TLS directory is smaller than the ${pointerSize * 8}-bit TLS header size (0x${fixture.headerSize.toString(16)} bytes).`
    ]);
  });

  void test(`TLS ${pointerSize}: finds TLS after unrelated directories`, async () => {
    const fixture = createTlsMappingFixture(pointerSize);
    fixture.directories.unshift({ name: "EXPORT", rva: 0, size: 0 });

    const tls = expectDefined(await fixture.parse());

    assert.equal(tls.parsed, true);
    assert.equal(tls.callbackTableStatus, "complete");
  });
}
