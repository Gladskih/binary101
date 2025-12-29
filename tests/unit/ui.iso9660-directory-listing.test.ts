"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { Iso9660DirectoryEntrySummary } from "../../analyzers/iso9660/types.js";
import { renderIso9660DirectoryListing } from "../../ui/iso9660-directory-listing.js";

void test("renderIso9660DirectoryListing renders actions, placeholders, and notices", () => {
  const entries: Iso9660DirectoryEntrySummary[] = [
    {
      name: "SUBDIR",
      kind: "directory",
      extentLocationLba: 10,
      dataLength: 4096,
      fileFlags: 0x02,
      recordingDateTime: "2018-11-02 00:00:00"
    },
    {
      name: "NOEXT",
      kind: "directory",
      extentLocationLba: null,
      dataLength: 2048,
      fileFlags: 0x02,
      recordingDateTime: null
    },
    {
      name: "FILE.BIN",
      kind: "file",
      extentLocationLba: 20,
      dataLength: 5,
      fileFlags: 0x00,
      recordingDateTime: null
    },
    {
      name: "MULTI.BIN",
      kind: "file",
      extentLocationLba: 30,
      dataLength: 5,
      fileFlags: 0x80,
      recordingDateTime: null
    },
    {
      name: "SPECIAL",
      kind: "special",
      extentLocationLba: null,
      dataLength: null,
      fileFlags: 0,
      recordingDateTime: null
    }
  ];

  const html = renderIso9660DirectoryListing({
    entries,
    totalEntries: entries.length,
    omittedEntries: 2,
    bytesRead: 2048,
    declaredSize: 8192,
    directoryPath: "/",
    depth: 0,
    isoBlockSize: 2048,
    containerIdPrefix: "isoDir",
    issues: ["Test notice"]
  });

  assert.ok(html.includes("isoDirToggleButton"));
  assert.ok(html.includes('data-iso-target="isoDir-dir-0"'));
  assert.ok(html.includes('id="isoDir-dir-0"'));

  assert.ok(html.includes("isoExtractButton"));
  assert.ok(html.includes('data-iso-offset="40960"'));
  assert.ok(html.includes('data-iso-length="5"'));
  assert.ok(html.includes('data-iso-name="FILE.BIN"'));

  assert.ok(html.includes("Multi-extent"));
  assert.ok(html.includes("Unavailable"));
  assert.ok(html.includes("2 more entries not shown."));
  assert.ok(html.includes("Notices:"));
  assert.ok(html.includes("Test notice"));
});

void test("renderIso9660DirectoryListing joins nested paths consistently", () => {
  const baseEntry: Iso9660DirectoryEntrySummary = {
    name: "INNER",
    kind: "directory",
    extentLocationLba: 1,
    dataLength: null,
    fileFlags: 0x02,
    recordingDateTime: null
  };

  const rootHtml = renderIso9660DirectoryListing({
    entries: [baseEntry],
    totalEntries: 1,
    omittedEntries: 0,
    bytesRead: 0,
    declaredSize: 0,
    directoryPath: "/",
    depth: 0,
    isoBlockSize: 2048,
    containerIdPrefix: "root",
    issues: []
  });
  assert.ok(rootHtml.includes('data-iso-path="/INNER"'));

  const slashHtml = renderIso9660DirectoryListing({
    entries: [baseEntry],
    totalEntries: 1,
    omittedEntries: 0,
    bytesRead: 0,
    declaredSize: 0,
    directoryPath: "/PARENT/",
    depth: 0,
    isoBlockSize: 2048,
    containerIdPrefix: "slash",
    issues: []
  });
  assert.ok(slashHtml.includes('data-iso-path="/PARENT/INNER"'));

  const trimmedChildHtml = renderIso9660DirectoryListing({
    entries: [{ ...baseEntry, name: "   " }],
    totalEntries: 1,
    omittedEntries: 0,
    bytesRead: 0,
    declaredSize: 0,
    directoryPath: "/PARENT",
    depth: 0,
    isoBlockSize: 2048,
    containerIdPrefix: "trim",
    issues: []
  });
  assert.ok(trimmedChildHtml.includes('data-iso-path="/PARENT"'));
});
