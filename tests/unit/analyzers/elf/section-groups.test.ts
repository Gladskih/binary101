import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfSectionGroups } from "../../../../analyzers/elf/section-groups.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";

const groupFixture = (order: "little" | "big" = "little") => {
  const fixture = relocationFixture(64, order);
  fixture.elf.sections[1]!.flags = 0x200n; // SHF_GROUP: gABI 3.9.
  fixture.elf.sections.push(relocationSection(4, { type: 17, offset: 64n, size: 8n,
    entsize: 4n, link: 2, info: 1 }));
  fixture.view.setUint32(64, 1, order === "little"); // GRP_COMDAT.
  fixture.view.setUint32(68, 1, order === "little"); // Member section #1.
  return fixture;
};

void test("reads COMDAT group members", async () => {
  const fixture = groupFixture();
  assert.deepEqual(await parseElfSectionGroups(fixture.file(), fixture.elf),
    [{ sectionIndex: 4, flags: 1, members: [1], issues: [] }]);
});

void test("reads big endian group words", async () => {
  const fixture = groupFixture("big");
  assert.deepEqual((await parseElfSectionGroups(fixture.file(), fixture.elf))[0]?.members, [1]);
});

void test("warns on truncated groups and invalid entry sizes", async () => {
  const fixture = groupFixture();
  fixture.elf.sections[4]!.size = 3n;
  assert.match((await parseElfSectionGroups(fixture.file(), fixture.elf))[0]!.issues.join(" "), /size/);
  fixture.elf.sections[4]!.entsize = 8n;
  assert.match((await parseElfSectionGroups(fixture.file(), fixture.elf))[0]!.issues.join(" "), /size/);
});

void test("warns on invalid member indices and missing group flags", async () => {
  const fixture = groupFixture();
  fixture.view.setUint32(68, 99, true);
  assert.match((await parseElfSectionGroups(fixture.file(), fixture.elf))[0]!.issues.join(" "), /member/);
  fixture.view.setUint32(68, 1, true);
  fixture.elf.sections[1]!.flags = 0n;
  assert.match((await parseElfSectionGroups(fixture.file(), fixture.elf))[0]!.issues.join(" "), /SHF_GROUP/);
});

void test("warns on duplicate memberships and invalid signatures", async () => {
  const fixture = groupFixture();
  fixture.elf.sections[4]!.size = 12n;
  fixture.elf.sections[4]!.info = 99;
  fixture.view.setUint32(72, 1, true);
  const groups = await parseElfSectionGroups(fixture.file(), fixture.elf);
  assert.match(groups[0]!.issues.join(" "), /signature/);
  assert.match(groups[0]!.issues.join(" "), /already/);
});

void test("warns on file bounds and unsupported flag bits", async () => {
  const fixture = groupFixture();
  fixture.view.setUint32(64, 2, true);
  assert.match((await parseElfSectionGroups(fixture.file(), fixture.elf))[0]!.issues.join(" "), /flags/);
  fixture.elf.sections[4]!.offset = 1n << 60n;
  assert.match((await parseElfSectionGroups(fixture.file(), fixture.elf))[0]!.issues.join(" "), /outside/);
});
