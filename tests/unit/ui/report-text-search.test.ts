import assert from "node:assert/strict";
import { test } from "node:test";
import { searchReportText } from "../../../ui/report-text-search.js";

void test("report search finds text outside the first displayed page", async () => {
  const entries = Array.from({ length: 501 }, (_, index) => ({ name: `symbol-${index}` }));

  const matches = await searchReportText({ exports: { entries } }, "SYMBOL-500",
    new AbortController().signal);

  assert.deepEqual(matches, [{ path: ["exports", "entries", 500, "name"], value: "symbol-500" }]);
});

void test("report search preserves Unicode, punctuation and markup literally", async () => {
  const matches = await searchReportText({ metadata: ["Автор <script>", "Καλημέρα"] },
    "автор <", new AbortController().signal);

  assert.deepEqual(matches, [{ path: ["metadata", 0], value: "Автор <script>" }]);
});

void test("report search skips binary buffers, functions and host objects", async () => {
  const matches = await searchReportText({ bytes: new Uint8Array([65]),
    view: new DataView(new ArrayBuffer(1)), buffer: new ArrayBuffer(1),
    file: new Blob(["needle"]), callback: () => "needle", name: "needle" }, "needle",
  new AbortController().signal);

  assert.deepEqual(matches, [{ path: ["name"], value: "needle" }]);
});

void test("report search tolerates cycles and repeated object references", async () => {
  const shared: { name: string; parent?: object } = { name: "needle" };
  const root = { first: shared, second: shared };
  shared.parent = root;

  assert.deepEqual(await searchReportText(root, "needle", new AbortController().signal),
    [{ path: ["first", "name"], value: "needle" }]);
});

void test("report search ignores empty queries and unsupported roots", async () => {
  const signal = new AbortController().signal;

  assert.deepEqual(await searchReportText({ value: "sample" }, "  ", signal), []);
  assert.deepEqual(await searchReportText(null, "sample", signal), []);
  assert.deepEqual(await searchReportText(new Uint8Array([1]), "1", signal), []);
  assert.deepEqual(await searchReportText({ value: "sample" }, "absent", signal), []);
});

void test("report search stops when a new query cancels it", async () => {
  const controller = new AbortController();
  controller.abort();

  await assert.rejects(searchReportText({ name: "sample" }, "sample", controller.signal),
    { name: "AbortError" });
});

void test("report search handles deeply nested parsed data without recursion overflow", async () => {
  let nested: object = { value: "needle" };
  for (let index = 0; index < 10000; index++) nested = { nested };

  const matches = await searchReportText(nested, "needle", new AbortController().signal);

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.path.length, 10001);
});

void test("report search yields even when parsed arrays contain no strings", async context => {
  const controller = new AbortController();
  let tick = 0;
  context.mock.method(performance, "now", () => tick++);
  const pending = searchReportText({ numbers: Array.from({ length: 1000 }, (_, index) => index) },
    "absent", controller.signal);
  setTimeout(() => controller.abort(), 0);

  await assert.rejects(pending, { name: "AbortError" });
});

void test("report search trims queries and visits dictionaries without prototypes", async () => {
  const dictionary = Object.create(null) as Record<string, string>;
  dictionary["name"] = "needle";

  assert.deepEqual(await searchReportText(dictionary, "  needle  ", new AbortController().signal),
    [{ path: ["name"], value: "needle" }]);
});

void test("report search excludes host-like instances with enumerable text", async () => {
  class ExternalObject { name = "needle"; }

  assert.deepEqual(await searchReportText({ external: new ExternalObject() }, "needle",
    new AbortController().signal), []);
});

void test("report search does not visit a self-referencing root twice", async () => {
  const root: { name: string; self?: object } = { name: "needle" };
  root.self = root;

  assert.deepEqual(await searchReportText(root, "needle", new AbortController().signal),
    [{ path: ["name"], value: "needle" }]);
});

void test("report search respects cancellation even with an empty input", async () => {
  const controller = new AbortController();
  controller.abort();

  await assert.rejects(searchReportText(null, "", controller.signal), { name: "AbortError" });
});

void test("report search discards results cancelled at its final yield", async context => {
  const controller = new AbortController();
  let tick = 0;
  context.mock.method(performance, "now", () => { tick += 10; return tick; });
  setTimeout(() => controller.abort(), 0);

  await assert.rejects(searchReportText({ name: "needle" }, "needle", controller.signal),
    { name: "AbortError" });
});
