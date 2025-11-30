"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { choosePreviewForFile } from "../../media-preview.js";

void test("prefers video preview when MIME type is already video", () => {
  const preview = choosePreviewForFile({
    fileName: "clip.mp4",
    mimeType: "video/mp4",
    typeLabel: "MP4/QuickTime container (ISO-BMFF)"
  });

  assert.deepEqual(preview, { kind: "video", mimeType: "video/mp4" });
});

void test("derives video type from ISO-BMFF label when MIME is blank", () => {
  const preview = choosePreviewForFile({
    fileName: "movie.bin",
    mimeType: "",
    typeLabel: "MP4/QuickTime container (ISO-BMFF)"
  });

  assert.deepEqual(preview, { kind: "video", mimeType: "video/mp4" });
});

void test("returns audio preview when MIME indicates audio", () => {
  const preview = choosePreviewForFile({
    fileName: "sound.bin",
    mimeType: "audio/mpeg",
    typeLabel: "MPEG audio stream (MP3/AAC)"
  });

  assert.deepEqual(preview, { kind: "audio", mimeType: "audio/mpeg" });
});

void test("returns image preview for HEIC even though ISO-BMFF is used", () => {
  const preview = choosePreviewForFile({
    fileName: "photo.heic",
    mimeType: "",
    typeLabel: "HEIF/HEIC image (ISO-BMFF)"
  });

  assert.deepEqual(preview, { kind: "image", mimeType: null });
});

void test("avoids flagging audio-only MPEG as video", () => {
  const preview = choosePreviewForFile({
    fileName: "song.mp3",
    mimeType: "audio/mpeg",
    typeLabel: "MPEG audio stream (MP3/AAC)"
  });

  assert.deepEqual(preview, { kind: "audio", mimeType: "audio/mpeg" });
});

void test("maps transport streams to a video preview type", () => {
  const preview = choosePreviewForFile({
    fileName: "capture.ts",
    mimeType: "application/octet-stream",
    typeLabel: "MPEG Transport Stream (TS)"
  });

  assert.deepEqual(preview, { kind: "video", mimeType: "video/mp2t" });
});
