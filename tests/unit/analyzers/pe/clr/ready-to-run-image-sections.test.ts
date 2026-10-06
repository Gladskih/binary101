import assert from "node:assert/strict";
import test from "node:test";
import { readyToRunImageSections } from
  "../../../../../analyzers/pe/clr/ready-to-run-image-sections.js";
import { createReadyToRunCompositeFixture } from "../../../../helpers/ready-to-run-composite-fixture.js";

void test("includes each decoded composite core directory once and preserves root sections", () => {
  const fixture = createReadyToRunCompositeFixture();
  fixture.component.coreHeader = { flags: 0, sectionCount: 1, sections: [
    { type: 106, name: "DelayLoadMethodCallThunks", rva: 0x300, size: 16 }]
  };
  const table = fixture.data.sections[1]!.decoded;
  assert.ok(table?.kind === "components");
  table.entries.push({ ...fixture.component });

  assert.deepEqual(readyToRunImageSections(fixture.data),
    [...fixture.data.sections, fixture.component.coreHeader.sections[0]]);
});

void test("keeps incomplete component rows without assuming a decoded header", () => {
  const fixture = createReadyToRunCompositeFixture();

  assert.deepEqual(readyToRunImageSections(fixture.data), fixture.data.sections);
  assert.deepEqual(readyToRunImageSections({ ...fixture.data, sections: [] }), []);
});
