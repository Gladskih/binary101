import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfLsdaActions } from "../../../../analyzers/elf/lsda-actions.js";
import { lsdaFixture } from "../../../fixtures/elf-lsda.js";

void test("follows displacement-field-relative actions once for shared call sites", async () => {
  const { result, cursorAt } = lsdaFixture([1, 1, 0, 0]);
  result.callSites = [0n, 1n, 1n].map(action => ({ start: 0n, length: 1n, landingPad: 1n, action }));
  await readElfLsdaActions(cursorAt, 0, 4, result);
  assert.deepEqual(result.actions, [{ offset: 0, typeFilter: 1n, nextOffset: 1n },
    { offset: 2, typeFilter: 0n, nextOffset: 0n }]);
  assert.deepEqual(result.issues, []);
});

void test("bounds action references, incomplete records and negative displacements", async () => {
  const { result, cursorAt } = lsdaFixture([0]);
  result.callSites = [{ start: 0n, length: 1n, landingPad: 1n, action: 2n }];
  await readElfLsdaActions(cursorAt, 0, 1, result);
  assert.match(result.issues.join(" "), /outside/);
  result.callSites[0]!.action = 1n;
  await readElfLsdaActions(cursorAt, 0, 1, result);
  assert.match(result.issues.join(" "), /Truncated/);
});
