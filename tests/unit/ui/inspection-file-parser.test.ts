import assert from "node:assert/strict";
import { test } from "node:test";
import { createInspectionFileParser } from "../../../ui/inspection-file-parser.js";
import { createWebmFile } from "../../fixtures/webm-base-fixtures.js";
import { createWebmWithDurationMismatch } from "../../fixtures/webm-duration-fixtures.js";
import { parseWebm } from "../../../analyzers/webm/index.js";

const parseOnTestThread = (file: File, signal: AbortSignal,
  onProgress: (position: number, total: number) => void) => parseWebm(file, { signal, onProgress });

const progressControls = () => {
  const attributes = new Set<string>();
  let value = 0;
  const bar = { get value() { return value; },
    set value(next: number) { value = next; attributes.add("value"); },
    hasAttribute: (name: string) => attributes.has(name),
    removeAttribute: (name: string) => { attributes.delete(name); } };
  const progress = { hidden: true };
  const label = { textContent: "old" };
  return { bar, progress, label };
};

void test("inspection parser reports real EBML progress and clears it on completion", async () => {
  const controls = progressControls();
  let cleared = 0;
  const parser = createInspectionFileParser(controls.progress, controls.bar, controls.label,
    () => cleared++, parseOnTestThread);

  const result = await parser.parse(createWebmWithDurationMismatch());

  assert.equal(result.analyzer, "webm");
  assert.equal(cleared, 1);
  assert.equal(controls.progress.hidden, false);
  assert.match(controls.label.textContent!, /^\d+%$/);
  assert.ok(controls.bar.value > 0);
  parser.finish();
  assert.equal(controls.progress.hidden, true);
  parser.cancel();
});

void test("a replacement file cancels an outstanding EBML parse", async () => {
  const controls = progressControls();
  const parser = createInspectionFileParser(controls.progress, controls.bar, controls.label,
    () => undefined, parseOnTestThread);

  const pending = parser.parse(createWebmFile());
  parser.cancel();

  await assert.rejects(pending, { name: "AbortError" });
  assert.equal(controls.progress.hidden, true);
});

void test("unknown files do not display invented parsing progress", async () => {
  const controls = progressControls();
  const parser = createInspectionFileParser(controls.progress, controls.bar, controls.label,
    () => assert.fail("EBML only"));

  assert.deepEqual(await parser.parse(new File([], "empty.bin")), { analyzer: null, parsed: null });
  assert.equal(controls.progress.hidden, true);
});
