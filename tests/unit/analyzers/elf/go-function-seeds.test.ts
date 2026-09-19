import assert from "node:assert/strict";
import { test } from "node:test";
import { collectGoFunctionSeeds } from "../../../../analyzers/elf/go-function-seeds.js";
import { createGoRuntimeFixture } from "../../../fixtures/go-runtime.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";
import { MockFile } from "../../../helpers/mock-file.js";
import type { GoRuntimeLayout } from "../../../../analyzers/go-runtime/types.js";

const fixture = (layout: GoRuntimeLayout = "go1.20+", width: 4 | 8 = 8) => {
  const runtime = createGoRuntimeFixture(layout, width, 0x400000n);
  const bytes = new Uint8Array(runtime.headerBytes.length + 64);
  bytes.set(runtime.headerBytes);
  return { bytes, text: runtime.textAddress, sections: [
    relocationSection(1, { name: ".gopclntab", addr: runtime.pcHeaderAddress,
      size: BigInt(runtime.headerBytes.length) }),
    // SHF_EXECINSTR=4; 64 bytes of executable fixture code.
    relocationSection(2, { name: ".text", addr: runtime.textAddress, flags: 4n,
      offset: BigInt(runtime.headerBytes.length), size: 64n })
  ] };
};

for (const layout of ["go1.16-1.17", "go1.18-1.19", "go1.20+"] as const) {
  for (const width of [4, 8] as const) {
    void test(`ELF reuses validated ${layout} ${width}-byte Go function metadata`, async () => {
      const subject = fixture(layout, width);
      const issues: string[] = [];
      assert.deepEqual(await collectGoFunctionSeeds(new MockFile(subject.bytes), subject.sections, issues),
        [{ source: ".gopclntab functions", vaddrs: [subject.text, subject.text + 32n] }]);
      assert.deepEqual(issues, []);
    });
  }
}

void test("rejects corrupt metadata and absent executable mapping without guessing", async () => {
  const subject = fixture();
  subject.bytes[0] = 0;
  const issues: string[] = [];
  assert.deepEqual(await collectGoFunctionSeeds(new MockFile(subject.bytes), subject.sections, issues), []);
  assert.equal(issues.length, 1);
  assert.deepEqual(await collectGoFunctionSeeds(new MockFile(subject.bytes), [], []), []);
  assert.deepEqual(await collectGoFunctionSeeds(new MockFile(subject.bytes), subject.sections.slice(0, 1), []), []);
});

void test("supports PIE section names and does not trust the unrelocated textStart", async () => {
  const subject = fixture();
  subject.sections[0]!.name = ".data.rel.ro.gopclntab";
  // pcHeader.textStart is the third pointer word for Go 1.18+.
  new DataView(subject.bytes.buffer).setBigUint64(24, 0n, true);
  assert.equal((await collectGoFunctionSeeds(new MockFile(subject.bytes), subject.sections, []))[0]
    ?.vaddrs[0], subject.text);
});

for (const length of [0n, 7n, 8n, 32n, 128n, 10000n]) {
  void test(`rejects truncated or out-of-file Go function sections of size ${length}`, async () => {
    const subject = fixture();
    subject.sections[0]!.size = length;
    const issues: string[] = [];
    assert.deepEqual(await collectGoFunctionSeeds(new MockFile(subject.bytes), subject.sections, issues), []);
    assert.equal(issues.length, 1);
  });
}

for (const width of [0, 1, 16]) {
  void test(`rejects invalid Go pointer width ${width}`, async () => {
    const subject = fixture();
    subject.bytes[7] = width;
    const issues: string[] = [];
    assert.deepEqual(await collectGoFunctionSeeds(new MockFile(subject.bytes), subject.sections, issues), []);
    assert.equal(issues.length, 1);
  });
}

void test("requires function metadata and code to stay inside their file sections", async () => {
  const subject = fixture();
  const issues: string[] = [];
  subject.sections[1]!.size = 32n;
  assert.deepEqual(await collectGoFunctionSeeds(new MockFile(subject.bytes), subject.sections, issues), []);
  subject.sections[1]!.size = 10000n;
  assert.deepEqual(await collectGoFunctionSeeds(new MockFile(subject.bytes), subject.sections, issues), []);
  subject.sections[1]!.size = 64n;
  subject.sections[1]!.flags = 0n;
  assert.deepEqual(await collectGoFunctionSeeds(new MockFile(subject.bytes), subject.sections, issues), []);
  assert.equal(issues.length, 3);
});
