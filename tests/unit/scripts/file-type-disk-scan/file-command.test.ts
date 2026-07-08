"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFileOutput } from "../../../../scripts/file-type-disk-scan/file-command.js";

void test("parseFileOutput accepts RFC 6838 media type names", () => {
  assert.deepEqual(parseFileOutput("application/vnd.example+json"), {
    status: "ok",
    mimeType: "application/vnd.example+json"
  });
});

void test("parseFileOutput reports file.exe access diagnostics as errors", () => {
  const message = "cannot open `C:\\locked.dat' (Permission denied)";
  assert.deepEqual(parseFileOutput(message), { status: "error", message });
});

void test("parseFileOutput rejects empty and malformed output", () => {
  assert.deepEqual(parseFileOutput(""), {
    status: "error",
    message: "file.exe returned empty output."
  });
  assert.deepEqual(parseFileOutput("application/octet-stream; charset=binary"), {
    status: "error",
    message: "application/octet-stream; charset=binary"
  });
});
