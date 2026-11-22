"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { renderElfLinking } from "../../../../renderers/elf/linking.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

void test("renderElfLinking renders interpreter and DT_NEEDED libraries", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const out: string[] = [];
  renderElfLinking(elf, out);
  const html = out.join("");
  assert.ok(html.includes("Dynamic linking"));
  assert.ok(html.includes(expected.interpreter));
  assert.ok(html.includes(expectDefined(expected.needed[0])));
  assert.ok(html.includes(expectDefined(expected.needed[1])));
  assert.ok(html.includes(expected.soname));
  assert.ok(html.includes(expected.runpath));
  assert.ok(html.includes("DT_FLAGS"));
  assert.ok(html.includes("DF_TEXTREL"));
  assert.ok(html.includes("DF_STATIC_TLS"));
  assert.ok(html.includes("UNKNOWN_BITS_0x1220"));
  assert.ok(html.includes("DT_FLAGS_1"));
  assert.ok(html.includes("DF_1_NODELETE"));
  assert.ok(html.includes("DF_1_INITFIRST"));
  assert.ok(html.includes("DF_1_NOOPEN"));
  assert.match(html, /class="opt sel"[^>]*>DF_TEXTREL<\/span>/);
  assert.match(html, /class="opt dim"[^>]*>DF_ORIGIN<\/span>/);
  assert.match(html, /class="opt sel"[^>]*>DF_1_NODELETE<\/span>/);
});

void test("dynamic linking escapes interpreter and dynamic warnings", () => {
  const elf = relocationFixture().elf;
  elf.interpreter = { path: "<loader>", issues: ["<bad interpreter>"] };
  elf.dynamic = { entries: [{ tag: 15, value: 1n, string: "<path>" }],
    needed: [], soname: null, rpath: "<path>", runpath: null,
    init: null, fini: null, preinitArray: null, initArray: null, finiArray: null,
    flags: null, flags1: null, issues: ["<bad flags>"], arrayIssues: ["<bad array>"],
    consistencyIssues: ["<bad string bounds>"] };
  const out: string[] = [];
  renderElfLinking(elf, out);
  assert.ok(out.join("").includes("&lt;bad interpreter>"));
  assert.ok(out.join("").includes("&lt;bad flags>"));
  assert.ok(out.join("").includes("&lt;bad array>"));
  assert.ok(out.join("").includes("&lt;bad string bounds>"));
  assert.ok(out.join("").includes("&lt;path&gt;"));
  assert.doesNotMatch(out.join(""), /<bad|<path/);
});

void test("dynamic linking renders a clean table without array diagnostics", () => {
  const elf = relocationFixture().elf;
  elf.dynamic = { entries: [], needed: [], soname: null, rpath: null, runpath: null,
    init: null, fini: null, preinitArray: null, initArray: null, finiArray: null,
    flags: null, flags1: null, issues: [] };
  const out: string[] = [];

  renderElfLinking(elf, out);

  assert.match(out.join(""), /Dynamic linking/);
  assert.doesNotMatch(out.join(""), /Notes/);
});

void test("dynamic linking handles interpreter-only files and absent metadata", () => {
  const elf = relocationFixture().elf;
  delete elf.dynamic;
  delete elf.interpreter;
  const out: string[] = [];

  renderElfLinking(elf, out);
  assert.deepEqual(out, []);
  elf.interpreter = { path: "<loader>", issues: [] };
  renderElfLinking(elf, out);

  assert.ok(out.join("").includes("&lt;loader>"));
  assert.ok(!out.join("").includes("DT_FLAGS"));
});
