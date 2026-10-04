"use strict";

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { parseClrAssemblyName } from "../../../../../../analyzers/pe/clr/metadata-assembly-name.js";

void test("reads assembly display names and normalized version/culture/token fields", () => {
  assert.deepEqual(parseClrAssemblyName(" Library, Version=01.02.3.4, Culture=EN-us, PublicKeyToken=null"),
    { name: "library", version: "1.2.3.4", culture: "en-us", publicKeyToken: "" });
  assert.deepEqual(parseClrAssemblyName("Library, Version=1.2.65535.0, Culture=Neutral, PublicKeyToken=0123456789ABCDEF"),
    { name: "library", version: "1.2", culture: "", publicKeyToken: "0123456789abcdef" });
  assert.deepEqual(parseClrAssemblyName("Library, Version=1.2.3.65535"), { name: "library", version: "1.2.3" });
});

void test("accepts public keys, runtime display flags and unknown desktop-compatible attributes", () => {
  assert.deepEqual(parseClrAssemblyName("Library, PublicKey=01234567, Retargetable=Yes, ProcessorArchitecture=MSIL, Unknown=value"),
    { name: "library", publicKeyToken: createHash("sha1").update(Uint8Array.of(1, 0x23, 0x45, 0x67))
      .digest().subarray(-8).reverse().toString("hex"), processorArchitecture: 1 });
  assert.deepEqual(parseClrAssemblyName("Library, Retargetable=No, ContentType=WindowsRuntime, PublicKey=\"\""),
    { name: "library", contentType: 0x200, publicKeyToken: "" });
});

void test("handles quoted and escaped assembly-name tokens", () => {
  assert.deepEqual(parseClrAssemblyName("' Odd,Library ', Culture='neutral'"), { name: " odd,library ", culture: "" });
  assert.deepEqual(parseClrAssemblyName("Odd\\,Library, Unknown=hello\\n\\t\\r\\=\\'\\\"\\\\"), { name: "odd,library" });
  assert.deepEqual(parseClrAssemblyName("Library, PublicKeyToken=\"\""), { name: "library", publicKeyToken: "" });
  assert.deepEqual(parseClrAssemblyName("Space Library   , Unknown='value'"), { name: "space library" });
  assert.deepEqual(parseClrAssemblyName("'\\\\\\=\\'\\\"\\t\\r\\n'"), { name: "\\='\"\t\r\n" });
  assert.deepEqual(parseClrAssemblyName("Library, PublicKey=NULL"), { name: "library", publicKeyToken: "" });
  assert.deepEqual(parseClrAssemblyName("Library, constructor=value, __proto__=value, tostring=ignored"),
    { name: "library" });
});

for (const name of ["", "Library,", "Library, Value", "Library, =x", "Library, Culture=a, Culture=b",
  "Library, PublicKey=ab, PublicKeyToken=null", "Library, Retargetable=Maybe", "Library, Retargetable=Yes, Retargetable=No",
  "Library, ProcessorArchitecture=Other", "Library, ContentType=Default", "Library, Version=65535.0",
  "Library, Version=1.2.65536", "Library, Version=1", "Library, Version=1.2.3.4.5", "Library, PublicKey=x0",
  "Library, PublicKey=abc", "Library, PublicKeyToken=ab", "Library, PublicKeyToken=zzzzzzzzzzzzzzzz",
  "Library, Culture=a=b", "\"Library\"x", "Lib\"rary", "Library\\", "Library\\z", "Lib\0rary", "'Library",
  "'Lib\0rary'", "\"Library\"\0", "Library, Version=1.65535", "Lib'rary", "Library=Unknown=value"]) {
  void test(`rejects malformed assembly display name ${JSON.stringify(name)}`, () => {
    assert.equal(parseClrAssemblyName(name), null);
  });
}

for (const [name, architecture] of [["x86", 2], ["ia64", 3], ["amd64", 4], ["arm", 5]] as const) {
  void test(`reads runtime processor architecture ${name}`, () => {
    assert.deepEqual(parseClrAssemblyName(`Library, ProcessorArchitecture=${name}`),
      { name: "library", processorArchitecture: architecture });
  });
}

for (const token of ["x0123456789abcdef", "0123456789abcdefx"]) {
  void test(`rejects extra characters around public-key token ${token}`, () => {
    assert.equal(parseClrAssemblyName(`Library, PublicKeyToken=${token}`), null);
  });
}

for (const flag of ["xYes", "Nox"]) {
  void test(`rejects extra characters around retargetable flag ${flag}`, () => {
    assert.equal(parseClrAssemblyName(`Library, Retargetable=${flag}`), null);
  });
}
