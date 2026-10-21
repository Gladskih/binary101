import assert from "node:assert/strict";
import { test } from "node:test";
import {
  renderHeaderOptions, renderMachine, renderOsAbi
} from "../../../../renderers/elf/header-options.js";

void test("OS ABI chips preserve registered, unrecognized and processor-specific codes", () => {
  assert.match(renderOsAbi(3), /class="opt sel"[^>]*>GNU\/Linux<\/span>/);
  assert.match(renderOsAbi(63), /class="opt sel"[^>]*>Unrecognized \(63\)<\/span>/);
  assert.match(renderOsAbi(64), /class="opt sel"[^>]*>Architecture-specific \(64\)<\/span>/);
  assert.equal((renderOsAbi(3).match(/>GNU\/Linux<\/span>/g) ?? []).length, 1);
  assert.equal((renderOsAbi(3).match(/class="opt sel"/g) ?? []).length, 1);
  assert.doesNotMatch(renderOsAbi(3), /Unrecognized \(3\)/);
  assert.match(renderOsAbi(64), /This value is outside the global OS ABI list/);
});

void test("machine chips select the exact code and retain the other possible machines", () => {
  assert.match(renderMachine(62), /^<div class="optionsRow"><span class="opt sel"/);
  assert.match(renderMachine(62), />x86-64<\/span>/);
  assert.match(renderMachine(65535), />Unknown machine \(65535\)<\/span>/);
  assert.match(renderMachine(62), /Other machine values/);
  assert.equal((renderMachine(62).match(/>x86-64<\/span>/g) ?? []).length, 1);
  assert.equal((renderMachine(62).match(/class="opt sel"/g) ?? []).length, 1);
  assert.ok(renderMachine(62).endsWith("</details>"));
  assert.match(renderMachine(65535), /Unassigned or vendor-specific e_machine value/);
  assert.match(renderMachine(62), /class="opt dim"[^>]*>SPARC<\/span>/);
});

void test("header choices select known values and retain unknown numeric values", () => {
  assert.match(renderHeaderOptions(1, [[1, "One", "Known option"]]), /class="opt sel"/);
  assert.match(renderHeaderOptions(9, [[1, "One"]]), /class="opt dim"/);
  assert.match(renderHeaderOptions(9, []), />Unknown \(9\)<\/span>/);
  assert.equal((renderHeaderOptions(1, [[1, "One"]]).match(/class="opt sel"/g) ?? []).length, 1);
  assert.equal((renderHeaderOptions(9, [[1, "One"]]).match(/class="opt sel"/g) ?? []).length, 1);
  assert.match(renderHeaderOptions(9, []), /This numeric code is not in the recognized values/);
});
