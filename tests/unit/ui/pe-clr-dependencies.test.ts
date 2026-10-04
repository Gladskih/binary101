"use strict";

import assert from "node:assert/strict";
import { test, type TestContext } from "node:test";
import { createClrDependencyChangeHandler, attachClrDependencyInputs } from "../../../ui/pe-clr-dependencies.js";
import { createBasePe } from "../../fixtures/pe-renderer-headers-fixture.js";
import { clrResolutionFixture } from "../../helpers/clr-resolution-fixture.js";
import { clrAssemblyDependencyFile } from "../../helpers/clr-dependency-file.js";
import { makeClr } from "../../helpers/pe-strong-name-fixture.js";
import { MockFile } from "../../helpers/mock-file.js";

class DependencyInput {
  files: File[] | null = [clrAssemblyDependencyFile()];
  disabled = false;
  value = "Library.dll";
  attributes = new Set(["data-clr-dependencies"]);
  hasAttribute(name: string): boolean { return this.attributes.has(name); }
}

const installInput = (context: TestContext): DependencyInput => {
  const previous = Object.getOwnPropertyDescriptor(globalThis, "HTMLInputElement");
  Object.defineProperty(globalThis, "HTMLInputElement", { configurable: true, value: DependencyInput });
  context.after(() => {
    if (previous) Object.defineProperty(globalThis, "HTMLInputElement", previous);
    else Reflect.deleteProperty(globalThis, "HTMLInputElement");
  });
  return new DependencyInput();
};

const currentPe = () => {
  const pe = createBasePe();
  pe.clr = makeClr(0, 0);
  pe.clr.meta!.tables = clrResolutionFixture();
  return pe;
};

const changeEvent = (target: unknown): Event => ({ target } as Event);

void test("loads selected assemblies, refreshes metadata and caches identical File objects", async context => {
  const input = installInput(context);
  const pe = currentPe();
  const original = pe.clr!.meta!.tables;
  const statuses: string[] = [];
  const updated: unknown[] = [];
  const handler = createClrDependencyChangeHandler(() => pe,
    message => statuses.push(message), value => updated.push(value));
  const pending = handler(changeEvent(input));
  assert.equal(input.disabled, true);
  assert.deepEqual(statuses, ["Reading local assembly dependencies..."]);
  await pending;
  assert.equal(input.disabled, false);
  assert.equal(input.value, "");
  assert.notStrictEqual(pe.clr!.meta!.tables, original);
  assert.deepEqual(updated, [pe]);
  assert.equal(statuses.at(-1), "Loaded 1 local assembly dependencies.");
  const file = input.files![0]!;
  file.slice = () => { throw new Error("must reuse parsed File"); };
  input.files = [file, file];
  await handler(changeEvent(input));
  assert.equal(statuses.at(-1), "Loaded 1 local assembly dependencies.");
  assert.equal(pe.clr!.meta!.tables!.issues, undefined);
});

void test("exposes invalid dependency warnings and replaces the selected dependency set", async context => {
  const input = installInput(context);
  const pe = currentPe();
  pe.clr!.meta!.tables!.issues = ["Source metadata warning."];
  const statuses: string[] = [];
  const handler = createClrDependencyChangeHandler(() => pe, message => statuses.push(message), () => {});
  await handler(changeEvent(input));
  input.files = [new MockFile(new Uint8Array(), "bad.dll")];
  await handler(changeEvent(input));
  assert.match(pe.clr!.meta!.tables!.issues!.join(";"), /bad.dll: no Windows PE/);
  assert.equal(pe.clr!.meta!.tables!.issues![0], "Source metadata warning.");
  assert.equal(statuses.at(-1), "Loaded 0 local assembly dependencies.");
});

void test("discards completed work when the inspected file changes", async context => {
  const input = installInput(context);
  const pe = currentPe();
  const original = pe.clr!.meta!.tables;
  let reads = 0;
  const updates: unknown[] = [];
  await createClrDependencyChangeHandler(() => ++reads === 1 ? pe : null,
    () => {}, value => updates.push(value))(changeEvent(input));
  assert.strictEqual(pe.clr!.meta!.tables, original);
  assert.deepEqual(updates, []);
  assert.equal(input.disabled, false);
});

void test("reports invalid dependency files when the source has no existing diagnostics", async context => {
  const input = installInput(context);
  input.files = [new MockFile(new Uint8Array(), "bad.dll")];
  const pe = currentPe();
  await createClrDependencyChangeHandler(() => pe, () => {}, () => {})(changeEvent(input));
  assert.deepEqual(pe.clr!.meta!.tables!.issues, ["bad.dll: no Windows PE headers were found."]);
});

void test("ignores unrelated changes, empty selection and unavailable metadata", async context => {
  const input = installInput(context);
  const pe = createBasePe();
  const statuses: string[] = [];
  const handler = createClrDependencyChangeHandler(() => pe, message => statuses.push(message), () => {});
  await handler(changeEvent({}));
  input.attributes.clear();
  await handler(changeEvent(input));
  input.attributes.add("data-clr-dependencies");
  input.files = null;
  await handler(changeEvent(input));
  input.files = [];
  await handler(changeEvent(input));
  input.files = [clrAssemblyDependencyFile()];
  input.disabled = true;
  await createClrDependencyChangeHandler(() => currentPe(),
    message => statuses.push(message), () => {})(changeEvent(input));
  input.disabled = false;
  await handler(changeEvent(input));
  await createClrDependencyChangeHandler(() => null, message => statuses.push(message), () => {})(changeEvent(input));
  assert.deepEqual(statuses, []);
});

void test("keeps the latest selection and shares an in-flight dependency read", async context => {
  const first = installInput(context);
  const second = new DependencyInput();
  const file = first.files![0]!;
  second.files = [file];
  const slice = file.slice.bind(file);
  let reads = 0;
  file.slice = (...args) => { reads++; return slice(...args); };
  const pe = currentPe();
  const updated: unknown[] = [];
  const handler = createClrDependencyChangeHandler(() => pe, () => {}, value => updated.push(value));
  await Promise.all([handler(changeEvent(first)), handler(changeEvent(second))]);
  assert.deepEqual(updated, [pe]);
  assert.equal(reads, 1);
});

void test("attaches delegated changes and writes status only when the status element exists", async context => {
  const input = installInput(context);
  const pe = currentPe();
  const previous = Object.getOwnPropertyDescriptor(globalThis, "document");
  const status = { textContent: "" };
  let listener: ((event: Event) => void) | undefined;
  Object.defineProperty(globalThis, "document", { configurable: true, value: {
    getElementById: (name: string) => { assert.equal(name, "statusMessage"); return status; }
  } });
  context.after(() => {
    if (previous) Object.defineProperty(globalThis, "document", previous);
    else Reflect.deleteProperty(globalThis, "document");
  });
  const root = { addEventListener: (name: string, handler: (event: Event) => void) => {
    assert.equal(name, "change"); listener = handler;
  } } as unknown as ParentNode;
  let refreshed = false;
  attachClrDependencyInputs(root, () => pe, () => { refreshed = true; });
  listener!(changeEvent(input));
  await context.waitFor(() => assert.equal(refreshed, true));
  assert.equal(status.textContent, "Loaded 1 local assembly dependencies.");
  globalThis.document.getElementById = () => null;
  refreshed = false;
  listener!(changeEvent(input));
  await context.waitFor(() => assert.equal(refreshed, true));
  attachClrDependencyInputs(root, () => undefined, () => {});
  listener!(changeEvent(input));
  attachClrDependencyInputs(root, () => ({ ...pe, opt: null } as unknown as typeof pe), () => {});
  listener!(changeEvent(input));
});
