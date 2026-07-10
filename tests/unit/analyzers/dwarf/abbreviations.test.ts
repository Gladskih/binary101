"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseAbbreviationTable } from "../../../../analyzers/dwarf/abbreviations.js";
import type { DwarfSectionInput } from "../../../../analyzers/dwarf/types.js";
import {
  TEST_DWARF,
  encodeAbbreviationTable
} from "../../../fixtures/dwarf-fixture-encoding.js";
import { MockFile } from "../../../helpers/mock-file.js";

const parse = async (bytes: number[], offset = 0, issues: string[] = []) => {
  const file = new MockFile(Uint8Array.from(bytes));
  const section: DwarfSectionInput = {
    name: ".debug_abbrev",
    offset: 0,
    size: bytes.length,
    compressed: false
  };
  return parseAbbreviationTable(file, section, BigInt(offset), true, issues);
};

void test("parseAbbreviationTable rejects offsets outside the section", async () => {
  const issues: string[] = [];

  assert.equal(await parse(encodeAbbreviationTable([]), 1, issues), null);
  assert.ok(issues[0]?.includes("falls outside"));
});

void test("parseAbbreviationTable rejects duplicate abbreviation codes", async () => {
  const issues: string[] = [];
  const bytes = encodeAbbreviationTable([
    {
      code: TEST_DWARF.abbreviationCode.compileUnit,
      tag: TEST_DWARF.tag.compileUnit,
      children: TEST_DWARF.children.no,
      attributes: []
    },
    {
      code: TEST_DWARF.abbreviationCode.compileUnit,
      tag: TEST_DWARF.tag.compileUnit,
      children: TEST_DWARF.children.no,
      attributes: []
    }
  ]);

  assert.equal(await parse(bytes, 0, issues), null);
  assert.ok(issues[0]?.includes("Duplicate abbreviation code"));
});

void test("parseAbbreviationTable bounds tags and attribute identifiers", async () => {
  const aboveSafeInteger = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
  const tagIssues: string[] = [];
  const attributeIssues: string[] = [];

  assert.equal(await parse(encodeAbbreviationTable([{
    code: TEST_DWARF.abbreviationCode.compileUnit,
    tag: aboveSafeInteger,
    children: TEST_DWARF.children.no,
    attributes: []
  }]), 0, tagIssues), null);
  assert.equal(await parse(encodeAbbreviationTable([{
    code: TEST_DWARF.abbreviationCode.compileUnit,
    tag: TEST_DWARF.tag.compileUnit,
    children: TEST_DWARF.children.no,
    attributes: [{ name: aboveSafeInteger, form: TEST_DWARF.form.data1 }]
  }]), 0, attributeIssues), null);
  assert.ok(tagIssues[0]?.includes("tag exceeds"));
  assert.ok(attributeIssues[0]?.includes("attribute or form exceeds"));
});

void test("parseAbbreviationTable rejects invalid DW_CHILDREN encodings", async () => {
  const issues: string[] = [];

  assert.equal(await parse(encodeAbbreviationTable([{
    code: TEST_DWARF.abbreviationCode.compileUnit,
    tag: TEST_DWARF.tag.compileUnit,
    children: TEST_DWARF.invalid.children,
    attributes: []
  }]), 0, issues), null);
  assert.ok(issues[0]?.includes("Invalid DW_CHILDREN value"));
});
