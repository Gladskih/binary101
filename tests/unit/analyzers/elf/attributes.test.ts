import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfAttributes } from "../../../../analyzers/elf/attributes.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";

const attributes = (vendor: string, data: number[]) => {
  const fixture = relocationFixture();
  fixture.elf.header.machine = vendor === "aeabi" ? 40 : 243;
  const name = new TextEncoder().encode(`${vendor}\0`);
  const size = 1 + 4 + name.length + 5 + data.length;
  fixture.bytes[64] = 65;
  fixture.view.setUint32(65, size - 1, true);
  fixture.bytes.set(name, 69);
  fixture.bytes[69 + name.length] = 1;
  fixture.view.setUint32(70 + name.length, 5 + data.length, true);
  fixture.bytes.set(data, 74 + name.length);
  fixture.elf.sections.push(relocationSection(4, { type: 0x70000003, offset: 64n,
    size: BigInt(size), name: ".attributes" }));
  return fixture;
};

void test("reads ARM integer, name and compatibility attributes", async () => {
  const source = attributes("aeabi", [6, 10, 5, 65, 55, 0, 32, 1, 103, 110, 117, 0]);
  const result = await parseElfAttributes(source.file(), source.elf);
  assert.deepEqual(result[0]?.vendors[0]?.scopes[0]?.attributes, [
    { tag: 6n, value: 10n }, { tag: 5n, value: "A7" },
    { tag: 32n, value: { flag: 1n, vendor: "gnu" } }
  ]);
  assert.deepEqual(result[0]?.issues, []);
});

void test("reads RISC-V stack alignment and architecture string", async () => {
  const source = attributes("riscv", [4, 16, 5, 114, 118, 54, 52, 105, 0]);
  assert.deepEqual((await parseElfAttributes(source.file(), source.elf))[0]?.vendors[0]?.scopes[0], {
    tag: 1n, indices: [], attributes: [{ tag: 4n, value: 16n }, { tag: 5n, value: "rv64i" }]
  });
});

void test("reports invalid version, vendor bounds and truncated strings", async () => {
  const source = attributes("riscv", [5, 65]);
  assert.match((await parseElfAttributes(source.file(), source.elf))[0]!.issues.join(" "), /Unterminated/);
  source.view.setUint32(65, 0xffffffff, true);
  assert.match((await parseElfAttributes(source.file(), source.elf))[0]!.issues.join(" "), /length/);
  source.bytes[64] = 0;
  assert.match((await parseElfAttributes(source.file(), source.elf))[0]!.issues.join(" "), /version/);
});

void test("rejects undersized vendor and scope records and scopes crossing vendor boundaries", async () => {
  const source = attributes("aeabi", [6, 10]);
  source.view.setUint32(65, 4, true);
  assert.match((await parseElfAttributes(source.file(), source.elf))[0]!.issues.join(" "), /vendor length/);
  source.view.setUint32(65, 17, true);
  source.view.setUint32(76, 4, true);
  assert.match((await parseElfAttributes(source.file(), source.elf))[0]!.issues.join(" "), /scope length/);
  source.view.setUint32(76, 100, true);
  assert.match((await parseElfAttributes(source.file(), source.elf))[0]!.issues.join(" "), /scope length/);
});

void test("handles unsupported architectures, unavailable sections and absent section names", async () => {
  const source = attributes("riscv", [4, 16]);
  delete source.elf.sections[4]!.name;
  assert.deepEqual((await parseElfAttributes(source.file(), source.elf))[0]!.issues, []);
  source.elf.sections[4]!.flags = 0x800n;
  assert.match((await parseElfAttributes(source.file(), source.elf))[0]!.issues.join(" "), /compressed/);
  source.elf.sections[4]!.offset = 1n << 60n;
  assert.match((await parseElfAttributes(source.file(), source.elf))[0]!.issues.join(" "), /outside/);
  source.elf.header.machine = 62;
  assert.deepEqual(await parseElfAttributes(source.file(), source.elf), []);
});

void test("bounds truncated nested headers and vendor names", async () => {
  const source = attributes("aeabi", [6, 10]);
  source.elf.sections[4]!.size = 3n;
  assert.ok((await parseElfAttributes(source.file(), source.elf))[0]!.issues.length > 0);
  source.elf.sections[4]!.size = 22n;
  source.view.setUint32(65, 5, true);
  assert.match((await parseElfAttributes(source.file(), source.elf))[0]!.issues.join(" "), /Unterminated/);
  source.view.setUint32(65, 12, true);
  assert.ok((await parseElfAttributes(source.file(), source.elf))[0]!.issues.length > 0);
});
