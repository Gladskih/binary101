"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseAttachments } from "../../analyzers/webm/attachments.js";
import { ATTACHMENTS_ID } from "../../analyzers/webm/constants.js";
import { readElementAt } from "../../analyzers/webm/ebml.js";
import { createMkvFile } from "../fixtures/mkv-base-fixtures.js";
import { MockFile } from "../helpers/mock-file.js";

const findBytesOffset = (data: Uint8Array, needle: number[]): number | null => {
  if (needle.length === 0) return null;
  const limit = data.length - needle.length;
  for (let offset = 0; offset <= limit; offset += 1) {
    let matches = true;
    for (let index = 0; index < needle.length; index += 1) {
      if (data[offset + index] !== needle[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return offset;
  }
  return null;
};

void test("parseAttachments reads attached file metadata", async () => {
  const file = createMkvFile();
  const attachmentsId = [0x19, 0x41, 0xa4, 0x69];
  const attachmentsOffset = findBytesOffset(file.data, attachmentsId);
  assert.ok(attachmentsOffset != null);

  const issues: string[] = [];
  const attachmentsHeader = await readElementAt(file, attachmentsOffset!, issues);
  assert.ok(attachmentsHeader);
  assert.strictEqual(attachmentsHeader?.id, ATTACHMENTS_ID);

  const attachments = await parseAttachments(file, attachmentsHeader!, issues);
  assert.ok(attachments);
  assert.strictEqual(attachments.truncated, false);
  assert.strictEqual(attachments.files.length, 1);
  const [attached] = attachments.files;
  assert.ok(attached);
  assert.strictEqual(attached.fileName, "cover.jpg");
  assert.strictEqual(attached.mediaType, "image/jpeg");
  assert.strictEqual(attached.description, "Cover art");
  assert.strictEqual(attached.uid, 123);
  assert.strictEqual(attached.dataSize, 4);
  assert.strictEqual(attached.truncated, false);
});

void test("parseAttachments reports truncation", async () => {
  const full = createMkvFile();
  const truncated = new MockFile(
    full.data.slice(0, full.data.length - 2),
    "truncated.mkv",
    "video/x-matroska"
  );
  const attachmentsId = [0x19, 0x41, 0xa4, 0x69];
  const attachmentsOffset = findBytesOffset(truncated.data, attachmentsId);
  assert.ok(attachmentsOffset != null);

  const issues: string[] = [];
  const attachmentsHeader = await readElementAt(truncated, attachmentsOffset!, issues);
  assert.ok(attachmentsHeader);
  assert.strictEqual(attachmentsHeader?.id, ATTACHMENTS_ID);

  const attachments = await parseAttachments(truncated, attachmentsHeader!, issues);
  assert.ok(attachments.truncated);
  assert.ok(attachments.files.length >= 1);
  assert.ok(issues.length >= 1);
});

