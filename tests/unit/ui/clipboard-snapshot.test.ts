import assert from "node:assert/strict";
import { test } from "node:test";
import { captureClipboardEntries } from "../../../ui/clipboard-snapshot.js";

void test("captures each text representation synchronously without choosing one", async () => {
  let accessOpen = true;
  const pending = captureClipboardEntries(["text/plain", "text/html", "text/uri-list"]
    .map(type => ({ kind: "string", type, getAsString: callback => {
      assert.equal(accessOpen, true);
      callback(type);
    } })), []);
  accessOpen = false;
  assert.deepEqual(await pending, [
    { kind: "text", type: "text/plain", text: "text/plain" },
    { kind: "text", type: "text/html", text: "text/html" },
    { kind: "text", type: "text/uri-list", text: "text/uri-list" }
  ]);
});

void test("keeps files once alongside text and handles missing file-list entries", async () => {
  const file = new File(["file"], "sample.bin");
  assert.deepEqual(await captureClipboardEntries([
    { kind: "file", getAsFile: () => file },
    { kind: "string", getAsString: callback => { callback(""); } }
  ], [file]), [{ kind: "file", file }, { kind: "text", type: "", text: "" }]);
  assert.deepEqual(await captureClipboardEntries([], [file]), [{ kind: "file", file }]);
  assert.deepEqual(await captureClipboardEntries([{ kind: "file" }], [file]),
    [{ kind: "file", file }]);
});

void test("captures directory handles during the paste event", async () => {
  const handle = { kind: "directory", name: "folder", entries: async function* () {} };
  let accessOpen = true;
  const pending = captureClipboardEntries([{ kind: "file", getAsFileSystemHandle: async () => {
    assert.equal(accessOpen, true);
    return handle;
  } }], []);
  accessOpen = false;
  assert.deepEqual(await pending, [{ kind: "handle", handle }]);
});

void test("shows inaccessible entries and read errors instead of dropping them", async () => {
  const entries = await captureClipboardEntries([
    { kind: "file", type: "application/octet-stream" },
    { kind: "string", type: "text/plain", getAsString: () => { throw new Error("denied"); } },
    { kind: "custom", type: "custom/type" }
  ], []);
  assert.equal(entries.length, 3);
  assert.match(JSON.stringify(entries), /denied/);
  assert.match(JSON.stringify(entries), /application\/octet-stream/);
  assert.match(JSON.stringify(entries), /custom\/type/);
  assert.deepEqual(await captureClipboardEntries([], []), []);
});

void test("retains file handles without loading their bytes and labels unknown entries", async () => {
  const handle = { kind: "file", name: "sample.bin",
    getFile: async () => { throw new Error("must not read until selected"); } };
  assert.deepEqual(await captureClipboardEntries([
    { kind: "file", getAsFileSystemHandle: async () => handle }
  ], []), [{ kind: "handle", handle }]);
  assert.deepEqual(await captureClipboardEntries([{ kind: "custom" }], []),
    [{ kind: "unavailable", type: "custom",
      error: "The browser did not provide readable data for this item." }]);
});
