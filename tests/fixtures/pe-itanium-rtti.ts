import { MockFile } from "../helpers/mock-file.js";
import { createItaniumFixture } from "./itanium-rtti.js";
import {
  createMsvcRttiFixtureCore, createMsvcRttiFixtureSections,
  writeMsvcRttiFixtureHeaders, writeMsvcRttiFixtureRelocations
} from "./pe-msvc-rtti-pe.js";

export const createPeItaniumFixture = (width: 4 | 8 = 8) => {
  const fixture = createItaniumFixture(width);
  const bytes = new Uint8Array(0x2800);
  const view = new DataView(bytes.buffer);
  const sections = createMsvcRttiFixtureSections();
  const core = createMsvcRttiFixtureCore(width === 8 ? 0x8664 : 0x14c,
    width === 8 ? 0x20b : 0x10b, sections, false);
  core.coff.Characteristics = 2;
  core.opt.ImageBase = width === 8 ? 0x140000000n : 0x400000n;
  bytes.set(fixture.bytes, 0x400);
  const sites = new Set<number>();
  for (const [site, target] of fixture.image.pointers) {
    sites.add(0x2000 + site);
    const rva = target >= fixture.addresses.code
      ? 0x1000 + target - fixture.addresses.code : 0x2000 + target;
    if (width === 8) view.setBigUint64(0x400 + site, core.opt.ImageBase + BigInt(rva), true);
    else view.setUint32(0x400 + site, Number(core.opt.ImageBase) + rva, true);
  }
  const relocation = writeMsvcRttiFixtureRelocations(view, sites, 0);
  // The existing PE header writer supplies PE32+ headers; PE32 tests use core directly.
  writeMsvcRttiFixtureHeaders(bytes, view, 0x8664, 0x20b, sections,
    relocation.directorySize, false);
  if (width === 4) {
    for (const block of relocation.model.blocks) {
      for (const entry of block.entries) if (entry.type) entry.type = 3;
    }
  }
  return { bytes, view, core, relocations: relocation.model, addresses: fixture.addresses,
    reader: () => new MockFile(bytes),
    resultAddress: (address: number) => 0x2000 + address };
};
