import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSpgoDebug } from "../../../../renderers/pe/debug-spgo.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";

void test("SPGO retains escaped Unicode text without guessing its meaning", () => {
  const out: string[] = [];
  renderSpgoDebug({ ...createDebugViewEntry(18, 0, 128),
    spgo: { text: "<профиль>&😀" } }, out);
  assert.match(out.join(""), /SPGO text/);
  assert.match(out.join(""), /&lt;профиль&gt;&amp;😀/);
  assert.match(out.join(""), /UTF-16/);
  assert.doesNotMatch(out.join(""), /<профиль>|<table/);
});

void test("SPGO explains an empty string and omits absent payloads", () => {
  const out: string[] = [];
  renderSpgoDebug(createDebugViewEntry(18, 0, 0), out);
  assert.deepEqual(out, []);
  renderSpgoDebug({ ...createDebugViewEntry(18, 0, 128), spgo: { text: "" } }, out);
  assert.match(out.join(""), /\(empty\)/);
});
