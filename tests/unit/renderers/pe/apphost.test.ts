"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPeAppHost } from "../../../../renderers/pe/apphost.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";

void test("renderPeAppHost renders locator, binding, bundle header, and warnings", () => {
  const pe = createBasePe();
  pe.rvaToOff = rva => rva - 0x1000;
  pe.appHost = {
    locators: [{
      rva: 0x2000,
      bundleHeaderOffset: 0x800n,
      bundleHeader: {
        majorVersion: 6,
        minorVersion: 0,
        embeddedFileCount: 3,
        bundleId: "bundle<&>",
        depsJson: { offset: 0x300n, size: 0x20n },
        runtimeConfigJson: { offset: 0x320n, size: 0x30n },
        flags: 1n
      }
    }],
    bindings: [{ rva: 0x2100, kind: "managed-assembly", value: "App<&>.dll" }],
    issues: ["bad <field>"]
  };
  const out: string[] = [];

  renderPeAppHost(pe, out);
  const html = out.join("");

  assert.ok(html.includes(".NET apphost"));
  assert.ok(html.includes("single-file bundle v6.0"));
  assert.ok(html.includes("App&lt;&>.dll"));
  assert.ok(html.includes("bundle&lt;&>"));
  assert.ok(html.includes("0x00002000"));
  assert.ok(html.includes("0x00001000"));
  assert.ok(html.includes("bad &lt;field>"));
  assert.match(html, /<dt>Version<\/dt><dd>6\.0<\/dd>/);
  assert.match(html, /<dt>Embedded files<\/dt><dd>3<\/dd>/);
  assert.match(html, /<dt>deps.json<\/dt><dd>0x00000300 \+ 0x00000020<\/dd>/);
  assert.match(html, /<dt>runtimeconfig.json<\/dt><dd>0x00000320 \+ 0x00000030<\/dd>/);
  assert.match(html, /<dt>Flags<\/dt><dd>0x00000001<\/dd>/);
  assert.match(html, /<td class="num">0x00000800<\/td>/);
  assert.match(html, /<h4>Structural warnings<\/h4><ul class="smallNote">/);
  assert.match(html, /<th scope="col">Bundle locator<\/th>/);
  assert.match(html, /<th scope="col">Bundle header offset<\/th>/);
  assert.match(html, /<th scope="col">Location<\/th>/);
  assert.match(html, /<th scope="col">Interpretation<\/th>/);
});

void test("renderPeAppHost preserves negative offsets and invalid bundle IDs", () => {
  const pe = createBasePe();
  pe.appHost = {
    locators: [{ rva: 0, bundleHeaderOffset: -1n, bundleHeader: {
      majorVersion: 1, minorVersion: 0, embeddedFileCount: 1, bundleId: null,
      depsJson: { offset: -2n, size: 0n }
    } }],
    bindings: [], issues: []
  };
  const out: string[] = [];

  renderPeAppHost(pe, out);

  assert.match(out.join(""), /-0x00000001/);
  assert.match(out.join(""), /-0x00000002 \+ 0x00000000/);
  assert.match(out.join(""), /invalid UTF-8/);
  assert.doesNotMatch(out.join(""), /Managed binding candidate/);
});

void test("renderPeAppHost renders nothing without apphost metadata", () => {
  const pe = createBasePe();
  const out: string[] = [];

  renderPeAppHost(pe, out);

  assert.deepEqual(out, []);
});

void test("renderPeAppHost renders an unbound non-bundle template", () => {
  const pe = createBasePe();
  pe.appHost = {
    locators: [{ rva: 0x2000, bundleHeaderOffset: null }],
    bindings: [{ rva: 0x2100, kind: "unbound-placeholder", value: "placeholder" }],
    issues: []
  };
  const out: string[] = [];

  renderPeAppHost(pe, out);
  const html = out.join("");

  assert.ok(html.includes("native .NET launcher"));
  assert.ok(html.includes("unavailable"));
  assert.ok(html.includes("SDK template has not been bound"));
  assert.ok(!html.includes("Single-file bundle header"));
});

void test("renderPeAppHost shows every bundle header and uses tables for repeated data", () => {
  const pe = createBasePe();
  const header = { majorVersion: 1, minorVersion: 0, embeddedFileCount: 1, bundleId: "first" };
  pe.appHost = {
    locators: [
      { rva: 0, bundleHeaderOffset: 1n, bundleHeader: header },
      { rva: 1, bundleHeaderOffset: 2n, bundleHeader: { ...header, bundleId: "second" } }
    ],
    bindings: [{ rva: 2, kind: "managed-assembly", value: "candidate.dll" }],
    issues: []
  };
  const out: string[] = [];

  renderPeAppHost(pe, out);

  assert.match(out.join(""), /second/);
  assert.match(out.join(""), /<table/);
  assert.match(out.join(""), /candidate/i);
});
