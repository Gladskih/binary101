import assert from "node:assert/strict";
import { test } from "node:test";
import { elfSectionSegments } from "../../../../analyzers/elf/section-segments.js";
import { elfSegmentUnwindFixture } from "../../../fixtures/elf-unwind.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";

const segments = () => {
  const [load] = elfSegmentUnwindFixture().elf.programHeaders;
  return [load!, { ...load!, index: 1, type: 7, typeName: "PT_TLS", filesz: 16n }];
};

void test("maps TLS initializers to both segments and TLS zero-fill only to the TLS template", () => {
  // SHF_ALLOC | SHF_TLS, SHT_NOBITS=8. gABI 3.3 and 7.7.
  const data = relocationSection(1, { flags: 0x402n, offset: 64n, addr: 4096n, size: 16n });
  const zero = relocationSection(2, { flags: 0x402n, type: 8, offset: 80n, addr: 4112n, size: 16n });
  assert.deepEqual(elfSectionSegments(data, segments()).map(segment => segment.index), [0, 1]);
  assert.deepEqual(elfSectionSegments(zero, segments()).map(segment => segment.index), [1]);
});

void test("rejects mismatched offsets, nonallocated data and ranges outside segments", () => {
  const section = relocationSection(1, { flags: 2n, offset: 65n, addr: 4096n, size: 16n });
  assert.deepEqual(elfSectionSegments(section, segments()), []);
  section.offset = 64n;
  section.size = 73n;
  assert.deepEqual(elfSectionSegments(section, segments()), []);
  section.size = 16n;
  section.flags = 0n;
  assert.deepEqual(elfSectionSegments(section, segments()), []);
});
