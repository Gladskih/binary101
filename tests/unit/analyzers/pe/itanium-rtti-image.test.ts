import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeItaniumImage } from "../../../../analyzers/pe/itanium-rtti-image.js";
import { createPeItaniumFixture } from "../../../fixtures/pe-itanium-rtti.js";

void test("reads bounded data prefixes and verifies file-backed code", async () => {
  const fixture = createPeItaniumFixture();
  const image = createPeItaniumImage(fixture.reader(), fixture.core, 8)!;
  assert.equal((await image.read(0x2000, 16)).byteLength, 16);
  assert.equal((await image.read(0x3fff, 512)).byteLength, 1);
  assert.equal(image.isExecutable(0x1000), true);
  assert.equal(image.isExecutable(0x2000), false);
  assert.equal(image.isExecutable(0x5000), false);
});
for (const address of [-1, NaN, 0, 0x1000, 0x5000, 0x2000 + 0.5]) {
  void test(`rejects invalid data address ${address}`, async () => {
    const fixture = createPeItaniumFixture();
    const image = createPeItaniumImage(fixture.reader(), fixture.core, 8)!;
    assert.equal((await image.read(address, 8)).byteLength, 0);
  });
}
for (const size of [-1, 0, Infinity, 0.5]) {
  void test(`rejects invalid read length ${size}`, async () => {
    const fixture = createPeItaniumFixture();
    assert.equal((await createPeItaniumImage(fixture.reader(), fixture.core, 8)!
      .read(0x2000, size)).byteLength, 0);
  });
}
type Fixture = ReturnType<typeof createPeItaniumFixture>;
for (const [label, edit] of Object.entries({
  imageBase: (fixture: Fixture) => { fixture.core.opt.ImageBase = -1n; },
  imageSize: (fixture: Fixture) => { fixture.core.opt.SizeOfImage = NaN; },
  emptyImage: (fixture: Fixture) => { fixture.core.opt.SizeOfImage = 0; },
  smallImage: (fixture: Fixture) => { fixture.core.opt.SizeOfImage = 0x2000; },
  sectionOffset: (fixture: Fixture) => { fixture.core.sections[0]!.pointerToRawData = -1; },
  virtualOverlap: (fixture: Fixture) => { fixture.core.sections[1]!.virtualAddress = 0x1000; },
  rawAlias: (fixture: Fixture) => { fixture.core.sections[1]!.pointerToRawData = 0x200; }
})) {
  void test(`rejects invalid image ${label}`, () => {
    const fixture = createPeItaniumFixture();
    edit(fixture);
    assert.equal(createPeItaniumImage(fixture.reader(), fixture.core, 8), null);
  });
}
void test("uses raw size for zero virtual size and respects EOF", async () => {
  const fixture = createPeItaniumFixture();
  fixture.core.sections[1]!.virtualSize = 0;
  const reader = fixture.reader();
  const image = createPeItaniumImage({ ...reader, size: 0x408,
    read: reader.read.bind(reader), readBytes: reader.readBytes.bind(reader) }, fixture.core, 8)!;
  assert.equal((await image.read(0x2000, 16)).byteLength, 8);
  assert.equal((await image.read(0x2008, 8)).byteLength, 0);
  assert.equal(image.isExecutable(0x1000), true);
});
void test("does not treat virtual-only code as executable evidence", () => {
  const fixture = createPeItaniumFixture();
  fixture.core.sections[0]!.pointerToRawData = fixture.bytes.length;
  assert.equal(createPeItaniumImage(fixture.reader(), fixture.core, 8)!.isExecutable(0x1000), false);
});
