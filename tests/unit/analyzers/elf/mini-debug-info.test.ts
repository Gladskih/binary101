import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfMiniDebugInfo } from "../../../../analyzers/elf/mini-debug-info.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";

// xz of a Clang AArch64 object defining run, which branches to the external variant.
const compressedElf = Buffer.from(
  "/Td6WFoAAATm1rRGBMDdAdAFIQEWAAAAAAAAABrcOVLgAs8A1V0AP5FFhGg9iabanKbNqRgCpED5XMP9CnEo2McqCabT1fBPHzh9K" +
  "OygIqAZBN6z7ThaqvY4N4Nbio/HgJhAQY4PqxLy+ORadniLksLrrYywOYVb9n8d42HuHy0VAUJo5JlcEWxvj/6971rJje3vFfSg93" +
  "xT0rcr2pWAUj7OvrsuZUr3Xda/QWQLFSrl6uyGTa4dL2do0LAnXAZWoYHfIYWofoLjhWYfYdzyKqh0LSx02rrZBRYtH0wXFrwNo" +
  "qlkN4+bVTC4MgfjcBcu3kUr8EPRxfeOFxCzAAAAALQpwihDtJZ1AAH5AdAFAADOzjfsscRn+wIAAAAABFla", "base64"
);

const miniFixture = (bytes: Uint8Array) => {
  const fixture = relocationFixture();
  fixture.elf.header.machine = 183; // EM_AARCH64 matches the embedded ELF.
  const section = relocationSection(4, { name: ".gnu_debugdata", offset: 64n, size: BigInt(bytes.length) });
  fixture.bytes.set(bytes, 64);
  fixture.elf.sections.push(section);
  return { ...fixture, section };
};

void test("decodes the embedded ELF symbol table with its own section indices", async () => {
  const fixture = miniFixture(compressedElf);
  const result = await parseElfMiniDebugInfo(fixture.file(), fixture.elf);
  const run = result?.symbolTables.flatMap(table => table.entries).find(entry => entry.name === "run");
  assert.equal(result?.sections.find(section => section.index === run?.sectionIndex)?.name, ".text");
  assert.deepEqual(result?.issues, []);
});

void test("reports truncated XZ, unrelated machines and invalid section storage", async () => {
  const short = miniFixture(compressedElf.subarray(0, compressedElf.length - 12));
  assert.match((await parseElfMiniDebugInfo(short.file(), short.elf))!.issues.join(" "), /XZ decode failed/);
  const wrong = miniFixture(compressedElf);
  wrong.elf.header.machine = 62; // EM_X86_64 differs from the embedded ELF.
  const mismatch = await parseElfMiniDebugInfo(wrong.file(), wrong.elf);
  assert.match(mismatch!.issues.join(" "), /Embedded ELF machine/);
  assert.deepEqual(mismatch?.symbolTables, []);
  wrong.section.size = 2048n;
  assert.match((await parseElfMiniDebugInfo(wrong.file(), wrong.elf))!.issues.join(" "), /file range/);
  delete wrong.section.name;
  assert.equal(await parseElfMiniDebugInfo(wrong.file(), wrong.elf), null);
});
