/// <reference types="vite/client" />
import assert from "node:assert/strict";
import { test } from "node:test";
import { setImmediate } from "node:timers/promises";
import { attachExampleGallery } from "../../../ui/example-gallery.js";

class Button extends EventTarget {
  hidden = true;
  textContent = "";
  readonly attributes = new Map<string, string>();
  setAttribute(name: string, value: string): void { this.attributes.set(name, value); }
  removeAttribute(name: string): void { this.attributes.delete(name); }
  click(): void { this.dispatchEvent(new Event("click")); }
}

class Dialog extends EventTarget {
  open = false;
  showModal(): void { this.open = true; }
  close(): void {
    this.open = false;
    this.dispatchEvent(new Event("close"));
  }
}

interface SampleContainer {
  ownerDocument: { createElement: (tag: string) => Button | SampleContainer };
  textContent: string;
  appendChild<Child extends Button | SampleContainer>(child: Child): Child;
  setAttribute(name: string, value: string): void;
}

const mountGallery = (assets: Record<string, string>) => {
  const launch = new Button();
  const dialog = new Dialog();
  const status = { textContent: "" };
  const modalStatus = { textContent: "" };
  const buttons: Button[] = [];
  const modalButtons: Button[] = [];
  const headings: SampleContainer[] = [];
  const opened: Parameters<Parameters<typeof attachExampleGallery>[1]>[] = [];
  const parent = (children: Button[]): SampleContainer => ({
    ownerDocument,
    textContent: "",
    appendChild: child => {
      if (child instanceof Button) children.push(child);
      return child;
    },
    setAttribute: () => undefined
  });
  const body = {
    rows: modalButtons,
    insertRow: () => ({ insertCell: () => parent(modalButtons) })
  };
  const panel = Object.assign(dialog, { querySelector: (selector: string) =>
    selector === "tbody" ? body : modalStatus });
  const ownerDocument = { createElement: (tag: string) => {
    if (tag === "button") return new Button();
    const element = parent(buttons);
    if (tag === "h3") headings.push(element);
    return element;
  } };
  const groups = parent(buttons);
  const landing = { hidden: true, querySelector: (selector: string) =>
    selector === ".exampleGalleryLanding__groups" ? groups : status };
  // This fixture supplies the DOM methods used by the gallery, with real EventTarget listeners.
  const document: unknown = {
    querySelector: () => panel,
    getElementById: (id: string) => id === "galleryLanding" ? landing : launch,
    createElement: ownerDocument.createElement
  };
  const cancel = attachExampleGallery(document as Document, async (...args) => {
    opened.push(args);
  }, assets);
  return { launch, landing, dialog, status, modalStatus, buttons, modalButtons, headings, opened, cancel };
};

const wasmAsset = { "../generated/gallery/hello.wasm": "/assets/fixture.wasm" };

void test("keeps the gallery hidden when there are no generated examples", () => {
  const gallery = mountGallery({});

  assert.equal(gallery.landing.hidden, true);
  assert.equal(gallery.launch.hidden, true);
  assert.deepEqual(gallery.buttons, []);
  assert.deepEqual(gallery.headings, []);
});

void test("loads one available example as an inspector File", async context => {
  const fetch = context.mock.method(globalThis, "fetch", async () =>
    new Response("example bytes", { headers: { "Content-Type": "application/wasm" } }));
  const gallery = mountGallery(wasmAsset);
  const [sample] = gallery.buttons;

  assert.equal(gallery.landing.hidden, false);
  assert.equal(gallery.dialog.open, false);
  assert.equal(fetch.mock.callCount(), 0);
  assert.equal(sample?.textContent, "WebAssembly");
  assert.deepEqual(gallery.headings.map(heading => heading.textContent), ["Executables and objects"]);

  sample?.click();
  await setImmediate();
  assert.equal(fetch.mock.calls[0]?.arguments[0], "/assets/fixture.wasm");
  const opened = gallery.opened[0];
  assert.ok(opened);
  assert.equal(opened[0].name, "hello.wasm");
  assert.equal(opened[0].type, "application/wasm");
  assert.equal(await opened[0].text(), "example bytes");
  assert.deepEqual(opened[1], { source: "example", object: "file" });
  assert.equal(gallery.dialog.open, false);
});

for (const [failure, createResponse] of [
  ["a missing asset", () => new Response("Missing", { status: 404 })],
  ["an HTML fallback", () => new Response("<title>Missing</title>", {
    headers: { "Content-Type": "text/html; charset=utf-8" }
  })],
  ["an empty asset", () => new Response()]
] as const) {
  void test(`reports ${failure} and re-enables sample selection`, async context => {
    context.mock.method(globalThis, "fetch", async () => createResponse());
    const gallery = mountGallery(wasmAsset);
    const sample = gallery.buttons[0]!;

    sample.click();
    await setImmediate();
    assert.equal(gallery.status.textContent, "Unable to open hello.wasm. Try again.");
    assert.equal(sample.attributes.has("aria-disabled"), false);
    assert.deepEqual(gallery.opened, []);
  });
}

void test("ignores a second click and cancels the pending fetch on close", async context => {
  const response = Promise.withResolvers<Response>();
  const fetch = context.mock.method(globalThis, "fetch", (_url: string, init: RequestInit) => {
    init.signal?.addEventListener("abort", () => response.reject(init.signal?.reason));
    return response.promise;
  });
  const gallery = mountGallery(wasmAsset);
  const sample = gallery.modalButtons[0]!;

  gallery.launch.click();
  sample.click();
  sample.click();
  assert.equal(fetch.mock.callCount(), 1);
  assert.equal(sample.attributes.get("aria-disabled"), "true");
  gallery.dialog.close();
  await setImmediate();
  assert.deepEqual(gallery.opened, []);
  assert.equal(gallery.modalStatus.textContent, "");
  assert.equal(sample.attributes.has("aria-disabled"), false);
});

void test("discards bytes if the dialog closes before its queued close event", async context => {
  const response = Promise.withResolvers<Response>();
  context.mock.method(globalThis, "fetch", () => response.promise);
  const gallery = mountGallery(wasmAsset);

  gallery.launch.click();
  gallery.modalButtons[0]!.click();
  gallery.dialog.open = false;
  response.resolve(new Response("completed bytes"));
  await setImmediate();
  assert.deepEqual(gallery.opened, []);
});

void test("discards a welcome selection when a different file opens", async context => {
  const response = Promise.withResolvers<Response>();
  context.mock.method(globalThis, "fetch", () => response.promise);
  const gallery = mountGallery(wasmAsset);
  const sample = gallery.buttons[0]!;

  sample.click();
  gallery.cancel();
  assert.equal(sample.attributes.has("aria-disabled"), false);
  response.resolve(new Response("old example"));
  await setImmediate();
  assert.deepEqual(gallery.opened, []);
  assert.equal(gallery.status.textContent, "");
});

void test("closes the report dialog on successful selection and on navigation", async context => {
  context.mock.method(globalThis, "fetch", async () => new Response("example bytes"));
  const gallery = mountGallery(wasmAsset);

  gallery.launch.click();
  gallery.modalButtons[0]!.click();
  await setImmediate();
  assert.equal(gallery.opened[0]?.[0].name, "hello.wasm");
  assert.equal(gallery.dialog.open, false);

  gallery.launch.click();
  gallery.cancel();
  assert.equal(gallery.dialog.open, false);
});

void test("blocks clipboard paste and file drop inside the modal", () => {
  const gallery = mountGallery(wasmAsset);

  gallery.launch.click();
  const drop = new Event("drop", { cancelable: true });
  const paste = new Event("paste", { cancelable: true });
  assert.equal(gallery.dialog.dispatchEvent(drop), false);
  assert.equal(gallery.dialog.dispatchEvent(paste), false);
});
