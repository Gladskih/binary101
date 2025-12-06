"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ASF_HEADER_GUID,
  ASF_DATA_GUID,
  STREAM_TYPE_AUDIO,
  STREAM_TYPE_NAMES,
  GUID_NAMES
} from "../../analyzers/asf/constants.js";

void test("ASF constants expose core GUIDs and names", () => {
  assert.strictEqual(ASF_HEADER_GUID, "75b22630-668e-11cf-a6d9-00aa0062ce6c");
  assert.strictEqual(ASF_DATA_GUID, "75b22636-668e-11cf-a6d9-00aa0062ce6c");
  assert.strictEqual(STREAM_TYPE_NAMES[STREAM_TYPE_AUDIO], "Audio stream");
  assert.ok(GUID_NAMES[ASF_HEADER_GUID]?.toLowerCase().includes("header"));
});
