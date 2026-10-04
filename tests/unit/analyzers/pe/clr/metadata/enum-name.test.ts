"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSerializedEnumName } from "../../../../../../analyzers/pe/clr/metadata-enum-name.js";

void test("reads unqualified and fully assembly-qualified enum names", () => {
  assert.deepEqual(parseSerializedEnumName("Demo.Mode"), { typeName: "Demo.Mode", assembly: null });
  assert.deepEqual(parseSerializedEnumName("Demo.Outer+Mode, Library, Version=1.2.3.4, Culture=neutral, PublicKeyToken=0123456789ABCDEF"),
    { typeName: "Demo.Outer+Mode", assembly: { name: "library", version: "1.2.3.4", culture: "", publicKeyToken: "0123456789abcdef" } });
});

void test("retains escaped type punctuation and quoted assembly names", () => {
  assert.deepEqual(parseSerializedEnumName("Demo.Comma\\,Mode, \"Odd,Library\", Culture=en-US"),
    { typeName: "Demo.Comma\\,Mode", assembly: { name: "odd,library", culture: "en-us" } });
  assert.deepEqual(parseSerializedEnumName("Demo.Mode, Library, PublicKeyToken=null, ContentType=WindowsRuntime"),
    { typeName: "Demo.Mode", assembly: { name: "library", publicKeyToken: "", contentType: 0x200 } });
});

for (const name of ["", "Demo.Mode,", "Demo.Mode[]", "Demo.Mode*", "Demo.Mode&", "Demo.Mode\\",
  "Demo.Mode, Library, Version=65536.0.0.0", "Demo.Mode, Library, Version=1.2.3.4.5",
  "Demo.Mode, Library, PublicKeyToken=0123", "Demo.Mode, Library, Culture=a, Culture=b",
  "Demo.Mode, \"Library", "Demo.Mode, Library, ContentType=Other", "Demo.\\Mode", "Demo.A++B"]) {
  void test(`rejects malformed serialized enum name ${name}`, () => {
    assert.equal(parseSerializedEnumName(name), null);
  });
}

void test("preserves literal plus signs and significant trailing type-name whitespace", () => {
  assert.deepEqual(parseSerializedEnumName(" Demo.Outer\\+Mode , Library, Unknown=x"),
    { typeName: "Demo.Outer\\+Mode ", assembly: { name: "library" } });
});

void test("uses .NET whitespace rules while preserving a leading byte-order mark", () => {
  // Char.IsWhiteSpace includes NEXT LINE U+0085 and excludes ZERO WIDTH NO-BREAK SPACE U+FEFF.
  // https://learn.microsoft.com/en-us/dotnet/api/system.char.iswhitespace
  assert.deepEqual(parseSerializedEnumName("\u0085Demo.Mode"), { typeName: "Demo.Mode", assembly: null });
  assert.deepEqual(parseSerializedEnumName("\t\u0085Demo.Mode"), { typeName: "Demo.Mode", assembly: null });
  assert.deepEqual(parseSerializedEnumName("\ufeffDemo.Mode"), { typeName: "\ufeffDemo.Mode", assembly: null });
  assert.deepEqual(parseSerializedEnumName("Demo. Mode"), { typeName: "Demo. Mode", assembly: null });
});
