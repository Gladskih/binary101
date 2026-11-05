"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { linkerVersionHint } from "../../../../renderers/pe/linker-version.js";

// Independent expectations: Microsoft's compiler/toolset version table, Roslyn's
// Compilation.LinkerMajorVersion, BFD's vstamp writer, Open Watcom exepe.h,
// LLD Writer.cpp, and dnlib PEHeaders.cs. See docs/pe-linker-versions.md.
const fixedVersions: Array<[number, number, string]> = [
  [6, 0, "Microsoft LINK (Visual C++ 6.0 toolset) / TinyCC (fixed 6.0)"],
  [3, 0, "Go internal linker (fixed 3.0) / Free Pascal-style version 3.0.0"],
  [7, 0, "Microsoft LINK (Visual Studio .NET 2002 toolset)"],
  [7, 10, "Microsoft LINK 7.10 (Visual Studio .NET 2003 toolset)"],
  [8, 0, "Microsoft LINK (Visual Studio 2005 toolset)"],
  [9, 0, "Microsoft LINK (Visual Studio 2008 toolset)"],
  [10, 0, "Microsoft LINK (Visual Studio 2010 toolset)"],
  [11, 0, "Microsoft LINK (Visual Studio 2012 toolset) / dnlib PE writer default"],
  [12, 0, "Microsoft LINK (Visual Studio 2013 toolset)"],
  [14, 0, "Microsoft LINK (Visual Studio 2015 toolset) / LLVM lld-link (compatibility value)"],
  [48, 0, "Roslyn C# / .NET PEHeaderBuilder default"],
  [80, 0, "Roslyn Visual Basic"],
  [2, 18, "Open Watcom (fixed 2.18) / GNU ld/BFD-style version"]
];

// Free Pascal's internal PE writer packs release*10 + patch in the minor byte.
// Release names below are independently checked against its published archive.
const pascalVersions: Array<[number, number, string, string]> = [
  [2, 22, "2.2.2", " / GNU ld/BFD-style version"],
  [2, 24, "2.2.4", " / GNU ld/BFD-style version"],
  [2, 40, "2.4.0", " / GNU ld/BFD-style version"],
  [2, 42, "2.4.2", " / GNU ld/BFD-style version"],
  [2, 44, "2.4.4", " / GNU ld/BFD-style version"],
  [2, 60, "2.6.0", ""], [2, 62, "2.6.2", ""], [2, 64, "2.6.4", ""],
  [3, 2, "3.0.2", ""], [3, 4, "3.0.4", ""], [3, 20, "3.2.0", ""], [3, 22, "3.2.2", ""]
];

for (const [major, minor, release, otherNames] of pascalVersions) {
  void test(`recognizes Free Pascal's version convention at ${major}.${minor}`, () => {
    assert.equal(linkerVersionHint(major, minor),
      `${major}.${minor} (possible: Free Pascal-style version ${release}${otherNames})`);
  });
}

void test("labels the explicitly checked Free Pascal development version as development", () => {
  assert.equal(linkerVersionHint(3, 31),
    "3.31 (possible: Free Pascal internal linker (3.3.1 development version))");
});

for (const [major, minor, names] of fixedVersions) {
  void test(`explains linker ${major}.${minor} as possible producers`, () => {
    assert.equal(linkerVersionHint(major, minor), `${major}.${minor} (possible: ${names})`);
  });
}

// The entries are independent literal version pairs, not imported production ranges.
const toolsetVersions: Array<[number, string]> = [
  [10, "Visual Studio 2017"], [11, "Visual Studio 2017"], [16, "Visual Studio 2017"],
  [20, "Visual Studio 2019"], [21, "Visual Studio 2019"], [29, "Visual Studio 2019"],
  [30, "Visual Studio 2022"], [39, "Visual Studio 2022"], [40, "Visual Studio 2022"],
  [41, "Visual Studio 2022"], [44, "Visual Studio 2022"]
];

for (const [minor, family] of toolsetVersions) {
  void test(`preserves the actual two-component tool version 14.${minor}`, () => {
    assert.equal(linkerVersionHint(14, minor),
      `14.${minor} (possible: Microsoft LINK (${family} toolsets))`);
  });
}

for (const minor of [50, 51, 52]) {
  void test(`does not infer a specific IDE from decoupled MSVC 14.${minor}`, () => {
    assert.equal(linkerVersionHint(14, minor),
      `14.${minor} (possible: Microsoft LINK (MSVC 14.5x toolsets))`);
  });
}

for (const minor of [7, 8, 9, 19, 29, 33, 46, 47]) {
  void test(`recognizes the GNU/BFD header convention for known release 2.${minor}`, () => {
    assert.equal(linkerVersionHint(2, minor), `2.${minor} (possible: GNU ld/BFD-style version)`);
  });
}

const unknownVersions: Array<[number, number]> = [
  [0, 0], [13, 0], [7, 1], [14, 1], [14, 2], [14, 3], [14, 9], [14, 17], [14, 19],
  [14, 45], [14, 49], [14, 53], [14, 255], [2, 6], [2, 48], [2, 99], [6, 1],
  [48, 1], [80, 1], [3, 1], [3, 21], [3, 32], [255, 255], [-1, 0], [256, 0],
  [14, 20.5], [NaN, 0]
];

for (const [major, minor] of unknownVersions) {
  void test(`leaves unverified linker version ${major}.${minor} unattributed`, () => {
    assert.equal(linkerVersionHint(major, minor), `${major}.${minor}`);
  });
}
