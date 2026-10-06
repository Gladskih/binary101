import assert from "node:assert/strict";
import test from "node:test";
import { renderCompositeReadyToRun } from "../../../../renderers/pe/clr-advanced.js";
import { createReadyToRunCompositeFixture } from
  "../../../helpers/ready-to-run-composite-fixture.js";

void test("wraps CLR-free R2R data in a section whose body can mount lazily", () => {
  const readyToRun = createReadyToRunCompositeFixture().data;
  const out: string[] = [];

  renderCompositeReadyToRun({ readyToRun }, out);

  assert.match(out.join(""), /^<section class="peSection"><details/);
  assert.match(out.join(""), /ReadyToRun composite header/);
  assert.match(out.join(""), /class="peSectionBody"[\s\S]*ComponentAssemblies/);
  assert.match(out.join(""), /<\/details><\/div><\/details><\/section>$/);
});

void test("an absent exported header still produces a valid empty section shell", () => {
  const out: string[] = [];

  renderCompositeReadyToRun({}, out);

  assert.match(out.join(""), /class="peSectionBody"><\/div><\/details><\/section>$/);
  assert.doesNotMatch(out.join(""), /managed native header/);
});
