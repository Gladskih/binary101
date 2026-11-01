import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeRelocationDiscovery } from "../../../../analyzers/pe/relocation-discovery-state.js";
import { createNativeAotMetadataFixture } from "../../../helpers/pe-native-aot-metadata-fixture.js";
import { nativeDiscovery, msvcDiscovery, reorderedNativeDiscovery } from "../../../helpers/pe-relocation-discovery.js";
import { MockFile } from "../../../helpers/mock-file.js";

for (const width of [4, 8] as const) {
  void test(`prepares shared PE${width * 8} discovery without changing relocation order`, () => {
    const { fixture, state } = nativeDiscovery(width);
    assert.equal(state.nativeImage.pointerSize, width);
    assert.equal(state.msvcImage !== null, width === 8);
    assert.equal(state.nativeSites.values().next().value, fixture.modulePointerRva);
    assert.deepEqual(state.sites, [...state.sites].sort((left, right) => left - right));
    assert.equal(state.itaniumImage.pointers.size, 0);
  });
}

type Fixture = ReturnType<typeof createNativeAotMetadataFixture>;
for (const [label, edit] of Object.entries({
  machine: (fixture: Fixture) => { fixture.core.coff.Machine = 0xaa64; },
  magic: (fixture: Fixture) => { fixture.core.opt.Magic = 0x10b; },
  warnings: (fixture: Fixture) => { fixture.relocations.warnings = ["truncated"]; },
  stripped: (fixture: Fixture) => { fixture.core.coff.Characteristics = 1; },
  imageSize: (fixture: Fixture) => { fixture.core.opt.SizeOfImage = 0x1_0000_0001; },
  empty: (fixture: Fixture) => { fixture.relocations.blocks = []; fixture.relocations.totalEntries = 0; },
  duplicate: (fixture: Fixture) => {
    fixture.relocations.blocks[0]!.entries[1] = { ...fixture.relocations.blocks[0]!.entries[0]! };
  },
  image: (fixture: Fixture) => { fixture.core.opt.ImageBase = -1n; },
  unmappedStart: (fixture: Fixture) => {
    const map = fixture.core.rvaToOff;
    fixture.core.rvaToOff = rva => rva === 0x1000 ? null : map(rva);
  },
  unmappedEnd: (fixture: Fixture) => {
    const map = fixture.core.rvaToOff;
    fixture.core.rvaToOff = rva => rva === 0x1fff ? null : map(rva);
  },
  overlap: (fixture: Fixture) => { fixture.core.sections.push({ ...fixture.core.sections[0]! }); }
})) {
  void test(`keeps independent analyzer fallback for ${label}`, () => {
    const fixture = createNativeAotMetadataFixture();
    edit(fixture);
    assert.equal(createPeRelocationDiscovery(new MockFile(fixture.bytes), fixture.core,
      fixture.relocations), null);
  });
}

void test("requires relocation evidence", () => {
  const { fixture, reader } = nativeDiscovery();
  assert.equal(createPeRelocationDiscovery(reader, fixture.core, null), null);
});

void test("accepts the exclusive PE RVA boundary and unrelated flags", () => {
  const { fixture, reader } = nativeDiscovery();
  fixture.core.opt.SizeOfImage = 0x1_0000_0000;
  fixture.core.coff.Characteristics = 2;
  assert.ok(createPeRelocationDiscovery(reader, fixture.core, fixture.relocations));
});

void test("ignores empty physical sections without inventing a mapping", () => {
  const { fixture, reader } = nativeDiscovery();
  fixture.core.sections.push({ ...fixture.core.sections[0]!, virtualAddress: 0x3000,
    pointerToRawData: fixture.bytes.length, virtualSize: 0, sizeOfRawData: 0 });
  assert.ok(createPeRelocationDiscovery(reader, fixture.core, fixture.relocations));
});

void test("keeps relocation evidence but no data sites for executable-only images", () => {
  const { fixture, reader } = nativeDiscovery();
  // PE executable code + read + execute flags; not initialized non-executable data.
  fixture.core.sections[0]!.characteristics = 0x60000020;
  const state = createPeRelocationDiscovery(reader, fixture.core, fixture.relocations);
  assert.ok(state);
  assert.equal(state.nativeSites.size, 0);
  assert.equal(state.msvcSites.size, 0);
  assert.ok(state.sites.length);
});

void test("requires compatible mapping for every data section", () => {
  const { fixture, reader } = msvcDiscovery();
  const map = fixture.core.rvaToOff;
  fixture.core.rvaToOff = rva => rva === 0x3fff ? null : map(rva);
  assert.equal(createPeRelocationDiscovery(reader, fixture.core, fixture.relocations), null);
});

void test("does not require the core mapper to cover executable-only sections", () => {
  const { fixture, reader } = msvcDiscovery();
  const map = fixture.core.rvaToOff;
  fixture.core.rvaToOff = rva => rva === 0x1000 ? null : map(rva);
  assert.ok(createPeRelocationDiscovery(reader, fixture.core, fixture.relocations));
});

void test("checks only the smaller virtual data span", () => {
  const { fixture, reader } = nativeDiscovery();
  fixture.core.sections[0]!.virtualSize = 0x800;
  fixture.core.rvaToOff = rva => rva >= 0x1000 && rva < 0x1800 ? rva - 0x1000 : null;
  assert.ok(createPeRelocationDiscovery(reader, fixture.core, fixture.relocations));
});

void test("validates the raw span when VirtualSize is zero", () => {
  const { fixture, reader } = nativeDiscovery();
  fixture.core.sections[0]!.virtualSize = 0;
  const map = fixture.core.rvaToOff;
  fixture.core.rvaToOff = rva => rva === 0x1fff ? null : map(rva);
  assert.equal(createPeRelocationDiscovery(reader, fixture.core, fixture.relocations), null);
});

void test("clips mapping checks to the available physical tail", () => {
  const { fixture, reader } = nativeDiscovery();
  fixture.core.sections[0]!.pointerToRawData = 0x100;
  fixture.core.rvaToOff = rva => rva >= 0x1000 && rva < 0x1f00 ? 0x100 + rva - 0x1000 : null;
  assert.ok(createPeRelocationDiscovery(reader, fixture.core, fixture.relocations));
});

void test("orders reads physically when section RVA order differs", () => {
  const { state } = reorderedNativeDiscovery();
  assert.deepEqual(state.sites.slice(0, 3), [0x11080, 0x21080, 0x1080]);
});
