import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeElfPackageNote } from "../../../../analyzers/elf/package-note.js";

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

void test("preserves producer JSON text and the precision of custom numeric fields", () => {
  const json = '{"name":"café","custom":9007199254740993}';
  const issues: string[] = [];
  assert.equal(decodeElfPackageNote(utf8(`${json}\0\0`), issues), json);
  assert.deepEqual(issues, []);
});

void test("rejects missing NUL, nonzero padding, invalid UTF-8, nonobjects and invalid JSON", () => {
  const paddingErrors = [utf8("{}"), utf8("{}\0x"), utf8("\0"), new Uint8Array()].map(bytes => {
    const issues: string[] = [];
    assert.equal(decodeElfPackageNote(bytes, issues), null);
    return issues[0];
  });
  assert.deepEqual(paddingErrors, Array(4).fill(
    "FDO package metadata requires JSON text followed by a NUL terminator and zero padding."));
  const issues: string[] = [];
  const invalidUtf8 = Uint8Array.of(123, 34, 120, 34, 58, 34, 0xff, 34, 125, 0); // {"x":"<invalid>"}.
  assert.equal(decodeElfPackageNote(invalidUtf8, issues), null);
  assert.equal(decodeElfPackageNote(utf8("[]\0"), issues), null);
  assert.equal(decodeElfPackageNote(utf8("null\0"), issues), null);
  assert.equal(decodeElfPackageNote(utf8("{\0"), issues), null);
  assert.equal(decodeElfPackageNote(utf8("42\0"), issues), null);
  assert.deepEqual(issues, Array(5).fill("FDO package metadata is not a valid UTF-8 JSON object."));
});
