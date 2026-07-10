"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveDwarfString } from "../../../../analyzers/dwarf/strings.js";
import type {
  DwarfFormValue,
  DwarfSectionInput,
  DwarfSectionSource,
  DwarfUnitContext
} from "../../../../analyzers/dwarf/types.js";
import {
  TEST_DWARF,
  concatenateBytes,
  encodeCString,
  encodeUint32
} from "../../../fixtures/dwarf-fixture-encoding.js";
import { MockFile } from "../../../helpers/mock-file.js";

const createSections = (): {
  file: MockFile;
  sections: Map<string, DwarfSectionSource>;
} => {
  const contents = [
    {
      name: ".debug_str_offsets",
      bytes: concatenateBytes(
        encodeUint32(TEST_DWARF.sectionOffset.start),
        encodeUint32(Uint32Array.BYTES_PER_ELEMENT)
      )
    },
    {
      name: ".debug_str",
      bytes: concatenateBytes(
        encodeUint32(TEST_DWARF.sectionOffset.start),
        encodeCString("foo")
      )
    },
    { name: ".debug_line_str", bytes: encodeCString("bar") }
  ];
  let offset = 0;
  const sections = new Map<string, DwarfSectionInput>();
  contents.forEach(content => {
    sections.set(content.name, {
      name: content.name,
      offset,
      size: content.bytes.length,
      compressed: false
    });
    offset += content.bytes.length;
  });
  const file = new MockFile(
    Uint8Array.from(concatenateBytes(...contents.map(value => value.bytes)))
  );
  return {
    file,
    sections: new Map([...sections].map(([name, section]) => [name, {
      summary: section,
      section,
      reader: file,
      decoded: true
    }]))
  };
};

const resolve = async (
  value: DwarfFormValue | undefined,
  stringOffsetsBase: bigint | null,
  issues: string[] = []
): Promise<string | null> => {
  const fixture = createSections();
  const context: DwarfUnitContext = {
    version: TEST_DWARF.version.five,
    format: TEST_DWARF.format.dwarf32,
    addressSize: TEST_DWARF.addressSize.x64,
    stringOffsetsBase
  };
  return resolveDwarfString(fixture.sections, value, context, true, issues);
};

void test("resolveDwarfString resolves inline and section-offset strings", async () => {
  assert.equal(await resolve({ kind: "string", value: "inline" }, null), "inline");
  assert.equal(await resolve({
    kind: "string-offset",
    value: 0n,
    sectionName: ".debug_line_str"
  }, null), "bar");
});

void test("resolveDwarfString resolves indexed strings through .debug_str_offsets", async () => {
  assert.equal(await resolve({
    kind: "string-index",
    value: BigInt(TEST_DWARF.stringIndex.foo)
  }, 0n), "foo");
});

void test("resolveDwarfString reports missing bases, sections, and out-of-range offsets", async () => {
  const baseIssues: string[] = [];
  const offsetIssues: string[] = [];
  const fixture = createSections();
  fixture.sections.delete(".debug_line_str");

  assert.equal(await resolve({ kind: "string-index", value: 1n }, null, baseIssues), null);
  assert.ok(baseIssues.some(issue => issue.includes("str_offsets_base")));
  assert.equal(await resolve({
    kind: "string-offset",
    value: BigInt(fixture.file.size),
    sectionName: ".debug_str"
  }, null, offsetIssues), null);
  assert.ok(offsetIssues.some(issue => issue.includes("falls outside")));
  assert.equal(await resolveDwarfString(
    fixture.sections,
    { kind: "string-offset", value: 0n, sectionName: ".debug_line_str" },
    {
      version: TEST_DWARF.version.five,
      format: TEST_DWARF.format.dwarf32,
      addressSize: TEST_DWARF.addressSize.x64,
      stringOffsetsBase: null
    },
    true,
    offsetIssues
  ), null);
});

void test("resolveDwarfString ignores non-string form values", async () => {
  assert.equal(await resolve(undefined, null), null);
  assert.equal(await resolve({ kind: "unsigned", value: 1n }, null), null);
});
