import assert from "node:assert/strict";
import { test } from "node:test";
import { parseAniAnimation } from "../../../../../../analyzers/pe/resources/preview/ani-animation.js";
import { createAnimatedCursorResource } from "../../../../../fixtures/pe-resource-advanced-payloads.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

void test("reads real CUR frames, per-step rates and source frame order", () => {
  const issues: string[] = [];
  const animation = expectDefined(parseAniAnimation(createAnimatedCursorResource(), issues));

  assert.equal(animation.frames.length, 2);
  assert.match(animation.frames[0]?.url ?? "", /^data:image\/x-icon;base64,/);
  assert.deepEqual(animation.frames[0]?.hotspot, { x: 0, y: 0 });
  assert.deepEqual(animation.sequence, [1, 0]);
  assert.deepEqual(animation.rates, [6, 12]);
  assert.equal(animation.defaultJiffies, 6);
  assert.deepEqual(issues, []);
});

void test("preserves source frame numbering when an embedded directory is corrupt", () => {
  const bytes = createAnimatedCursorResource();
  bytes[124] = 255; // First CUR directory starts after RIFF/anih/rate/seq/LIST/icon headers.
  const issues: string[] = [];
  const animation = expectDefined(parseAniAnimation(bytes, issues));

  assert.equal(animation.frames.length, 2);
  assert.ok(issues.length);
  assert.equal(parseAniAnimation(new Uint8Array(), []), null);
});

void test("does not advertise arbitrary image bytes as a playable ICO frame", () => {
  const bytes = createAnimatedCursorResource();
  // First frame: RIFF/anih/rate/seq/LIST/icon (108 bytes), CUR directory (22 bytes).
  new DataView(bytes.buffer).setUint32(130, 1, true);
  const issues: string[] = [];
  const animation = expectDefined(parseAniAnimation(bytes, issues));

  assert.equal(animation.frames[0]?.url, "");
  assert.match(issues.join(" "), /image/);
});

const checkAniPrefixes = (bytes: Uint8Array): void => {
  for (let length = 12; length < bytes.length; length += 1) {
    const issues: string[] = [];
    assert.ok(parseAniAnimation(bytes.subarray(0,length),issues));
    assert.ok(issues.length > 0);
  }
};
void test("bounds-checks every truncated ANI prefix", () => {
  checkAniPrefixes(createAnimatedCursorResource());
});
void test("diagnoses header flags, sequence references and mismatching timing counts", () => {
  const bytes = createAnimatedCursorResource();
  const view = new DataView(bytes.buffer);
  view.setUint32(20,35,true); // anih cbSizeof.
  view.setUint32(28,3,true); // cSteps.
  view.setUint32(52,0,true); // Neither AF_ICON nor AF_SEQUENCE.
  view.setUint32(80,999,true); // First seq entry points outside the frame list.
  const issues: string[] = [];

  assert.ok(parseAniAnimation(bytes,issues));
  assert.match(issues.join(" "),/structure size.*raw bitmap.*missing frame.*unused.*rate length/su);
});
