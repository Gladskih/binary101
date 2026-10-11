"use strict";

import { MsvcRttiPeFixtureBuilder } from "./pe-msvc-rtti-fixture.js";

export const createPeDataSeedFixture = (names = [["?f@@YAHH@Z"],
  ["?value@demo@@3HA", "PlainAlias"], ["??_7Widget@@6B@"],
  ["?value@demo@@3HAtrailing"], ["PlainC"], [], ["?broken"]]) => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const type = builder.addType(".?AVSeedFixture@@");
  const hierarchy = builder.addHierarchy(type);
  const targets = names.map(() => builder.allocateFunctionTarget());
  builder.addVftable(hierarchy, targets);
  // Intentionally misleading data in executable .text: VADDPS / RET and MOVAPS / RET.
  // These bytes make false ISA findings observable, beyond merely counting seeds.
  builder.bytes.set([0xc5, 0xf8, 0x58, 0xc0, 0xc3], builder.offsetOf(targets[1]!));
  builder.bytes.set([0x0f, 0x28, 0xc0, 0xc3], builder.offsetOf(targets[2]!));
  const directory = builder.allocateData(40);
  const eat = builder.allocateData(targets.length * 4);
  const aliases = names.flatMap((items, index) => items.map(name => ({ name, index })));
  const pointers = builder.allocateData(aliases.length * 4);
  const ordinals = builder.allocateData(aliases.length * 2);
  const encoder = new TextEncoder();
  aliases.forEach(({ name, index }, alias) => {
    const rva = builder.allocateData(name.length + 1, 1);
    builder.bytes.set(encoder.encode(`${name}\0`), builder.offsetOf(rva));
    builder.patchUint32(pointers, alias * 4, rva);
    builder.view.setUint16(builder.offsetOf(ordinals) + alias * 2, index, true);
  });
  targets.forEach((rva, index) => builder.patchUint32(eat, index * 4, rva));
  for (const [offset, value] of [[16, 1], [20, targets.length], [24, aliases.length],
    [28, eat], [32, pointers], [36, ordinals]]) builder.patchUint32(directory, offset!, value!);
  const fixture = builder.build();
  // PE32+ optional-header data directories start at offset 112; export is index zero.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
  const view = new DataView(fixture.bytes.buffer);
  const optional = view.getUint32(0x3c, true) + 24;
  view.setUint32(optional + 112, directory, true);
  view.setUint32(optional + 116, 40, true);
  return { file: new File([Uint8Array.from(fixture.bytes)], "data-seeds.dll"), targets };
};
