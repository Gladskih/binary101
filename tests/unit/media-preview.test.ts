"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { choosePlayablePreviewCandidate, choosePreviewForFile } from "../../media-preview.js";

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

void test("choosePlayablePreviewCandidate falls back to label-derived video MIME", () => {
  const primary = choosePreviewForFile({
    fileName: "mislabeled.mpg",
    mimeType: "video/mpeg",
    typeLabel: "MP4/QuickTime container (ISO-BMFF)"
  });
  const derived = choosePreviewForFile({
    fileName: "mislabeled.mpg",
    mimeType: "",
    typeLabel: "MP4/QuickTime container (ISO-BMFF)"
  });

  const chosen = choosePlayablePreviewCandidate(primary, derived, {
    video: mimeType => (mimeType === "video/mp4" ? "maybe" : ""),
    audio: () => ""
  });

  assert.deepEqual(chosen, { kind: "video", mimeType: "video/mp4" });
});

void test("choosePlayablePreviewCandidate hides MPEG Program Stream previews when unsupported", () => {
  const primary = choosePreviewForFile({
    fileName: "clip.mpg",
    mimeType: "video/mpeg",
    typeLabel: "MPEG Program Stream (MPG)"
  });
  const derived = choosePreviewForFile({
    fileName: "clip.mpg",
    mimeType: "",
    typeLabel: "MPEG Program Stream (MPG)"
  });

  const chosen = choosePlayablePreviewCandidate(primary, derived, {
    video: () => "",
    audio: () => ""
  });

  assert.equal(chosen, null);
});

void test("choosePlayablePreviewCandidate returns primary when playability checks are missing", () => {
  const primary = choosePreviewForFile({
    fileName: "clip.mpg",
    mimeType: "video/mpeg",
    typeLabel: "MPEG Program Stream (MPG)"
  });

  assert.deepEqual(choosePlayablePreviewCandidate(primary, null, null), primary);
});
