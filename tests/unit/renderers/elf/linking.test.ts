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
  assert.ok(html.includes("Flags (DT_FLAGS)"));
  assert.ok(html.includes("DF_TEXTREL"));
  assert.ok(html.includes("DF_STATIC_TLS"));
  assert.ok(html.includes("UNKNOWN_BITS_0x1220"));
  assert.ok(html.includes("Flags_1 (DT_FLAGS_1)"));
  assert.ok(html.includes("DF_1_NODELETE"));
  assert.ok(html.includes("DF_1_INITFIRST"));
  assert.ok(html.includes("DF_1_NOOPEN"));
  assert.match(html, /class="opt sel"[^>]*>DF_TEXTREL<\/span>/);
  assert.match(html, /class="opt dim"[^>]*>DF_ORIGIN<\/span>/);
  assert.match(html, /class="opt sel"[^>]*>DF_1_NODELETE<\/span>/);
});

// glibc elf.h defines DF_* and DF_1_* below the high bit; preserve unknown bit 31.
// https://github.com/bminor/glibc/blob/master/elf/elf.h
for (const [flags, expected] of [
  [null, "-"], [0, '<div class="mono">0x00000000</div>'],
  [0x80000000, '<div class="mono">0x80000000</div>']
] as const) {
  void test(`dynamic flag chips preserve absent, zero and unknown values: ${flags}`, () => {
    const elf = relocationFixture().elf;
    elf.dynamic = { needed: [], soname: null, rpath: null, runpath: null,
      init: null, fini: null, preinitArray: null, initArray: null, finiArray: null,
      flags, flags1: flags, issues: [] };
    const out: string[] = [];

    renderElfLinking(elf, out);

    assert.ok(out.join("").includes(`>Flags (DT_FLAGS)</dt><dd>${expected}`));
    assert.ok(out.join("").includes(`>Flags_1 (DT_FLAGS_1)</dt><dd>${expected}`));
    assert.doesNotMatch(out.join(""), /class="opt sel"[^>]*>DF_/);
  });
}

void test("dynamic flag chips keep unknown high bits selected and escape diagnostics", () => {
  const elf = relocationFixture().elf;
  elf.interpreter = { path: "", issues: ["<bad interpreter>"] };
  elf.dynamic = { needed: [], soname: null, rpath: "<path>", runpath: null,
    init: null, fini: null, preinitArray: null, initArray: null, finiArray: null,
    flags: 0x80000000, flags1: 0x80000000, issues: ["<bad flags>"] };
  const out: string[] = [];

  renderElfLinking(elf, out);

  assert.match(out.join(""), /class="opt sel"[^>]*>UNKNOWN_BITS_0x80000000<\/span>/);
  assert.ok(out.join("").includes("&lt;bad interpreter>"));
  assert.ok(out.join("").includes("&lt;bad flags>"));
  assert.ok(out.join("").includes("&lt;path>"));
  assert.doesNotMatch(out.join(""), /<bad|<path/);
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
