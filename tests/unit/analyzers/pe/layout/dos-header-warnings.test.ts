"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeDosHeaderWarnings } from "../../../../../analyzers/pe/layout/dos-header-warnings.js";
import type { PeDosHeader } from "../../../../../analyzers/pe/types.js";

const createDosHeader = (overrides: Partial<PeDosHeader> = {}): PeDosHeader => ({
  e_magic: "MZ",
  e_cblp: 0x90,
  e_cp: 3,
  e_crlc: 0,
  e_cparhdr: 4,
  e_minalloc: 0,
  e_maxalloc: 0xffff,
  e_ss: 0,
  e_sp: 0xb8,
  e_csum: 0,
  e_ip: 0,
  e_cs: 0,
  e_lfarlc: 0x40,
  e_ovno: 0,
  e_res: [0, 0, 0, 0],
  e_oemid: 0,
  e_oeminfo: 0,
  e_res2: Array.from({ length: 10 }, () => 0),
  e_lfanew: 0x80,
  stub: { kind: "standard", note: "classic DOS message" },
  ...overrides
});

void test("collectPeDosHeaderWarnings accepts a conventional PE DOS header", () => {
  assert.deepEqual(collectPeDosHeaderWarnings(createDosHeader()), []);
});

void test("collectPeDosHeaderWarnings reports impossible PE DOS header spans", () => {
  const warnings = collectPeDosHeaderWarnings(createDosHeader({ e_cparhdr: 0 }));
  assert.ok(warnings.some(warning => /e_cparhdr 0 paragraph.*IMAGE_DOS_HEADER/i.test(warning)));
});

void test("collectPeDosHeaderWarnings reports DOS headers that overlap the PE signature", () => {
  const warnings = collectPeDosHeaderWarnings(createDosHeader({ e_cparhdr: 16 }));
  assert.ok(warnings.some(warning => /DOS header size .*extends past PE header offset/i.test(warning)));
});

void test("collectPeDosHeaderWarnings validates relocation table placement", () => {
  const fixedHeaderWarnings = collectPeDosHeaderWarnings(createDosHeader({ e_crlc: 1, e_lfarlc: 0x10 }));
  const declaredHeaderWarnings = collectPeDosHeaderWarnings(createDosHeader({ e_crlc: 2, e_lfarlc: 0x3c }));
  assert.ok(fixedHeaderWarnings.some(warning => /relocation table offset.*fixed MZ header/i.test(warning)));
  assert.ok(declaredHeaderWarnings.some(warning => /relocation table ends.*declared DOS header/i.test(warning)));
});

void test("collectPeDosHeaderWarnings reports entrypoints outside pre-PE stub bytes", () => {
  const warnings = collectPeDosHeaderWarnings(createDosHeader({ e_ip: 0x40 }));
  assert.ok(warnings.some(warning => /DOS entrypoint CS:IP resolves.*outside the DOS stub bytes/i.test(warning)));
});

void test("collectPeDosHeaderWarnings reports inconsistent legacy MZ size and memory fields", () => {
  const warnings = collectPeDosHeaderWarnings(
    createDosHeader({ e_cblp: 513, e_cp: 0, e_minalloc: 4, e_maxalloc: 2 })
  );
  assert.ok(warnings.some(warning => /e_cblp 513 exceeds/i.test(warning)));
  assert.ok(warnings.some(warning => /e_cp is zero/i.test(warning)));
  assert.ok(warnings.some(warning => /e_minalloc 4 is greater than e_maxalloc 2/i.test(warning)));
});
