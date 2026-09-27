import assert from "node:assert/strict";
import { test } from "node:test";
import { formatVirtualKey } from "../../../../../../analyzers/pe/resources/preview/virtual-key.js";

void test("formats function keys, digits, letters, OEM, IME, media and unknown virtual keys", () => {
  assert.equal(formatVirtualKey(0x70), "F1");
  assert.equal(formatVirtualKey(0x87), "F24");
  assert.equal(formatVirtualKey(0x30), "0");
  assert.equal(formatVirtualKey(0x39), "9");
  assert.equal(formatVirtualKey(0x41), "A");
  assert.equal(formatVirtualKey(0x5a), "Z");
  assert.equal(formatVirtualKey(0x60), "VK_NUMPAD0");
  assert.equal(formatVirtualKey(0xba), "VK_OEM_1");
  assert.equal(formatVirtualKey(0x15), "VK_KANA");
  assert.equal(formatVirtualKey(0xb3), "VK_MEDIA_PLAY_PAUSE");
  assert.equal(formatVirtualKey(0x24), "VK_HOME");
  assert.equal(formatVirtualKey(0), "VK_0x00");
});
