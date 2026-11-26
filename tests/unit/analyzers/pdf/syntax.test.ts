import assert from "node:assert/strict";
import { test } from "node:test";
import {
  readArray, readDictionary, readIntegerArray, readName, readReference, skipTrivia, unsigned
} from "../../../../analyzers/pdf/syntax.js";

void test("PDF whitespace excludes vertical tab and includes NUL, form feed and comments", () => {
  const text = "payload\0\t\f \r% not a token\r\n\v";
  assert.equal(skipTrivia(text, 7), text.length - 1);
  assert.equal(skipTrivia(text, text.length), text.length);
});

void test("dictionary stops at delimiters outside strings and preserves direct values", () => {
  const raw = "<< /Ty#70e/Catalog /Meta << /N -.25 >> /Array [+3. 9.375 .25 true false null /] " +
    "/Nested (a(b\\)c)d) /Hex <01\tA> /Reference 32% separator\r\n2 R >>";
  const prefix = "skip\n";
  const dictionary = readDictionary(prefix + raw + " suffix", prefix.length);
  assert.equal(dictionary?.end, prefix.length + raw.length);
  assert.equal(dictionary?.raw, raw);
  assert.deepEqual(Array.from(dictionary?.fields ?? []), [
    ["Type", "/Catalog"], ["Meta", "<< /N -.25 >>"], ["Array", "[+3. 9.375 .25 true false null /]"],
    ["Nested", "(a(b\\)c)d)"], ["Hex", "<01\tA>"], ["Reference", "32% separator\r\n2 R"]
  ]);
});

for (const value of ["1junk", "junk2", ".x", "3.5extra", "R", "[1 0 Rx]", "1 0 Ray"]) {
  void test("dictionary rejects an invalid value token " + value, () => {
    assert.equal(readDictionary("<< /N " + value + " >>"), null);
  });
}

void test("array retains whole objects and rejects trailing data after its closing delimiter", () => {
  assert.deepEqual(readArray("[ 4 0 R /Name (x) [1] << /N null >> ]"),
    ["4 0 R", "/Name", "(x)", "[1]", "<< /N null >>"]);
  assert.deepEqual(readArray("[]"), []);
  assert.equal(readArray(undefined), null);
  assert.equal(readArray("[0] trailer"), null);
});

void test("integer arrays require every item to fit a nonnegative safe integer", () => {
  assert.deepEqual(readIntegerArray("[+1 0 9007199254740991]"), [1, 0, Number.MAX_SAFE_INTEGER]);
  assert.equal(readIntegerArray("[1 -2]"), null);
  assert.equal(readIntegerArray("[0 9007199254740992]"), null);
  assert.equal(readIntegerArray("not an array"), null);
  assert.equal(unsigned("3suffix"), null);
});

void test("name and reference readers preserve escaped names and full object identity", () => {
  assert.equal(readName(undefined), null);
  assert.equal(readName("Catalog"), null);
  assert.equal(readName("/#41#42#43"), "ABC");
  // PDF Reference, Table 3.16: the stored generation has a maximum of 65535.
  assert.deepEqual(readReference("37 65535 R"), { objectNumber: 37, generation: 65535 });
});

for (const token of ["", "0 5 R", "1 65536 R", "1 9007199254740992 R", "1 R", "3 0 R extra"]) {
  void test("indirect reference rejects " + JSON.stringify(token), () => {
    assert.equal(readReference(token), null);
  });
}

void test("applies the same nesting budget to dictionaries and arrays", () => {
  const nested = (opening: string, closing: string, depth: number) =>
    "<< /Root " + opening.repeat(depth) + "0" + closing.repeat(depth) + " >>";
  assert.ok(readDictionary(nested("[", "]", 63)));
  assert.equal(readDictionary(nested("[", "]", 64)), null);
  assert.ok(readDictionary(nested("<< /X ", " >>", 63)));
  assert.equal(readDictionary(nested("<< /X ", " >>", 64)), null);
});
