import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfAttributes } from "../../../../analyzers/elf/attributes.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";

// Arm buildattr64: each vendor block includes its own u32 length, unlike the nested ARM scopes.
const subsection = (name: string, framing: number[], data: number[]): Uint8Array => {
  const vendor = new TextEncoder().encode(`${name}\0`);
  const bytes = new Uint8Array(4 + vendor.length + framing.length + data.length);
  new DataView(bytes.buffer).setUint32(0, bytes.length, true);
  bytes.set(vendor, 4);
  bytes.set(framing, 4 + vendor.length);
  bytes.set(data, 4 + vendor.length + framing.length);
  return bytes;
};

const attributes = (...subsections: Uint8Array[]) => {
  const fixture = relocationFixture();
  fixture.elf.header.machine = 183;
  const offset = 64;
  fixture.bytes[offset] = 65; // A format version.
  let end = offset + 1;
  for (const item of subsections) {
    fixture.bytes.set(item, end);
    end += item.length;
  }
  fixture.elf.sections.push(relocationSection(4, { type: 0x70000003, offset: BigInt(offset),
    size: BigInt(end - offset), name: ".ARM.attributes" }));
  return fixture;
};

void test("reads public integer and private string subsections, retaining raw tag numbers", async () => {
  const fixture = attributes(subsection("aeabi_feature_and_bits", [1, 0], [0, 1, 2, 0]),
    subsection("private", [1, 1], [0x81, 1, 65, 0]));
  const [parsed] = await parseElfAttributes(fixture.file(), fixture.elf);
  assert.deepEqual(parsed?.vendors.map(vendor => vendor.aarch64), [
    { comprehension: 1, parameterType: 0, attributes: [{ tag: 0n, value: 1n }, { tag: 2n, value: 0n }] },
    { comprehension: 1, parameterType: 1, attributes: [{ tag: 129n, value: "A" }] }
  ]);
  assert.deepEqual(parsed?.issues, []);
});

void test("bounds bad encodings, duplicate vendors and partial subsections", async () => {
  const fixture = attributes(subsection("private", [2, 3], []), subsection("private", [1, 1], [1, 65]));
  const [parsed] = await parseElfAttributes(fixture.file(), fixture.elf);
  assert.match(parsed!.issues.join(" "), /parameter type 3.*comprehension value 2.*Unterminated.*Duplicate/);
  fixture.view.setUint32(65, 0xffff, true);
  const [truncated] = await parseElfAttributes(fixture.file(), fixture.elf);
  assert.match(truncated!.issues.join(" "), /subsection length/);
  assert.deepEqual(truncated?.vendors, []);
});
