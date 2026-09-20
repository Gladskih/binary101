import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBuildAttributeNote } from "../../../../analyzers/elf/build-attribute-note.js";
import type { ElfNoteEntry } from "../../../../analyzers/elf/types.js";

const note = (): ElfNoteEntry => ({ name: "GA", type: 0x100, source: "fixture",
  descSize: 0, typeName: null, description: null, value: null });
const range = (): Uint8Array => {
  const bytes = new Uint8Array(16);
  new DataView(bytes.buffer).setBigUint64(0, 0x1000n, true);
  new DataView(bytes.buffer).setBigUint64(8, 0x1100n, true);
  return bytes;
};

void test("GNU attributes decode binary values and inherit ranges of the same type", () => {
  const entry = note();
  const ranges = new Map<number, string>();
  const issues: string[] = [];
  // binutils common.h: '*' numeric, attribute 2 stack protector, value 3 strong.
  decodeBuildAttributeNote(entry, new Uint8Array([71, 65, 42, 2, 3, 0]), range(), "little", ranges, issues);
  assert.equal(entry.name, "Stack protector");
  assert.equal(entry.value, "strong");
  assert.match(entry.description!, /0x1000.*0x1100/);
  const inherited = note();
  decodeBuildAttributeNote(inherited, new TextEncoder().encode("GA+stack_clash\0"),
    new Uint8Array(), "little", ranges, issues);
  assert.equal(inherited.value, "true");
  assert.equal(inherited.name, "stack_clash");
  assert.equal(inherited.description, entry.description);
  assert.deepEqual(issues, []);
});

for (const [attribute, labels] of [
  [2, ["off", "on", "all", "strong", "explicit"]],
  [7, ["static", "pic", "PIC", "pie", "PIE"]]
] as const) {
  for (const [value, label] of labels.entries()) {
    void test(`GNU numeric attribute ${attribute} label ${label}`, () => {
      const entry = note();
      decodeBuildAttributeNote(entry, new Uint8Array([71, 65, 42, attribute, value, 0]),
        new Uint8Array(), "little", new Map(), []);
      assert.equal(entry.value, label);
    });
  }
}

for (const bytes of [[71, 65, 42, 4], [71, 65, 0], [71, 65, 63, 4, 0]]) {
  void test(`GNU rejects malformed name ${bytes}`, () => {
    const entry = note();
    const issues: string[] = [];
    decodeBuildAttributeNote(entry, new Uint8Array(bytes), new Uint8Array(), "little", new Map(), issues);
    assert.equal(entry.value, null);
    assert.match(issues.join(" "), /GNU build attribute/);
  });
}

void test("GNU numeric attributes accept exactly eight bytes and keep their little-endian order", () => {
  const entry = note();
  const issues: string[] = [];
  decodeBuildAttributeNote(entry, new Uint8Array([71, 65, 42, 4, 1, 2, 3, 4, 5, 6, 7, 8, 0]),
    new Uint8Array(), "big", new Map(), issues);
  assert.equal(entry.value, "0x807060504030201");
  assert.deepEqual(issues, []);
});

void test("GNU preserves string values after named attributes", () => {
  const entry = note();
  decodeBuildAttributeNote(entry, new TextEncoder().encode("GA$custom\0value\0"),
    new Uint8Array(), "little", new Map(), []);
  assert.equal(entry.name, "custom");
  assert.equal(entry.value, "value");
});

for (const order of ["little", "big"] as const) {
  void test(`GNU validates ${order}-endian 64-bit ranges, including empty ranges`, () => {
    const entry = note();
    const bytes = new Uint8Array(16);
    const view = new DataView(bytes.buffer);
    view.setBigUint64(0, 0x100000000n, order === "little");
    view.setBigUint64(8, 0x100000000n, order === "little");
    const issues: string[] = [];
    decodeBuildAttributeNote(entry, new TextEncoder().encode("GA+enabled\0"), bytes, order, new Map(), issues);
    assert.equal(entry.description, "0x100000000–0x100000000 (end exclusive)");
    assert.deepEqual(issues, []);
    view.setBigUint64(8, 1n, order === "little");
    decodeBuildAttributeNote(entry, new TextEncoder().encode("GA+enabled\0"), bytes, order, new Map(), issues);
    assert.equal(entry.description, "Range unavailable");
    assert.match(issues.join(" "), /Invalid GNU build attribute range/);
  });
}

void test("GNU attributes preserve zero bytes in numeric payloads", () => {
  const entry = note();
  decodeBuildAttributeNote(entry, new Uint8Array([71, 65, 42, 4, 0, 1, 0]),
    range(), "little", new Map(), []);
  assert.equal(entry.value, "0x100");
});

for (const [bytes, name, value] of [
  [[71, 65, 33, 3, 0], "RELRO", "false"],
  [[71, 65, 36, 5, 103, 99, 99, 0], "Compiler", "gcc"],
  [[42, 7, 4, 0], "PIC / PIE", "PIE"],
  [[71, 65, 42, 7, 9, 0], "PIC / PIE", "0x9"],
  [[71, 65, 42, 9, 0], "Attribute 9", "0x0"]
] as const) {
  void test(`GNU attribute ${name} = ${value}`, () => {
    const entry = note();
    const issues: string[] = [];
    decodeBuildAttributeNote(entry, new Uint8Array(bytes), range(), "little", new Map(), issues);
    assert.equal(entry.name, name);
    assert.equal(entry.value, value);
    assert.equal(entry.typeName, "GNU_BUILD_ATTRIBUTE_OPEN");
    assert.equal(entry.description, "0x1000–0x1100 (end exclusive)");
    assert.deepEqual(issues, []);
  });
}

void test("GNU function attributes isolate scope and invalidate broken inherited ranges", () => {
  const entry = { ...note(), type: 0x101 };
  const ranges = new Map([[0x100, "other scope"]]);
  const issues: string[] = [];
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setUint32(0, 16, false);
  new DataView(bytes.buffer).setUint32(4, 32, false);
  decodeBuildAttributeNote(entry, new TextEncoder().encode("GA+enabled\0"), bytes, "big", ranges, issues);
  assert.equal(entry.typeName, "GNU_BUILD_ATTRIBUTE_FUNC");
  assert.equal(entry.description, "0x10–0x20 (end exclusive)");
  decodeBuildAttributeNote(entry, new TextEncoder().encode("GA+enabled\0"), bytes.subarray(0, 4),
    "big", ranges, issues);
  assert.equal(entry.description, "From 0x10");
  decodeBuildAttributeNote(entry, new TextEncoder().encode("GA+enabled\0"), bytes.subarray(0, 3),
    "big", ranges, issues);
  assert.equal(entry.description, "Range unavailable");
  assert.equal(ranges.has(0x101), false);
  assert.equal(ranges.get(0x100), "other scope");
});

void test("GNU attributes reject truncated names, oversized numbers and invalid ranges", () => {
  const issues: string[] = [];
  decodeBuildAttributeNote(note(), new Uint8Array([71, 65]), range(), "little", new Map(), issues);
  decodeBuildAttributeNote(note(), new Uint8Array([71, 65, 42, 4, ...new Array<number>(10).fill(1), 0]),
    new Uint8Array(3), "little", new Map(), issues);
  assert.match(issues.join("\n"), /name/);
  assert.match(issues.join("\n"), /numeric/);
  assert.match(issues.join("\n"), /range/);
});
