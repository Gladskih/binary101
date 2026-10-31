import assert from "node:assert/strict";
import { test, type TestContext } from "node:test";
import { createEmbeddedResourceClickHandler } from "../../../ui/embedded-resource-actions.js";
import { detectEmbeddedResources } from "../../../analyzers/embedded-resources/detect.js";
import { minimalRcc, embeddedResourceFixture } from "../../fixtures/embedded-resource-builders.js";
import { createBasePe } from "../../fixtures/pe-renderer-headers-fixture.js";
import { MockFile } from "../../helpers/mock-file.js";

const installDom = (context: TestContext) => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { Element: globals["Element"], document: globals["document"],
    create: URL.createObjectURL, revoke: URL.revokeObjectURL };
  class Button {
    dataset: Record<string, string> = { embeddedResourceBundle: "0", embeddedResourceEntry: "1" };
    disabled = false;
    closest(): Button { return this; }
  }
  let blob: Blob | null = null;
  const anchor = { href: "", download: "", click: () => {} };
  const revoked: string[] = [];
  globals["Element"] = Button;
  globals["document"] = { createElement: () => anchor };
  URL.createObjectURL = value => { blob = value as Blob; return "blob:resource"; };
  URL.revokeObjectURL = url => { revoked.push(url); };
  context.after(() => {
    globals["Element"] = original.Element;
    globals["document"] = original.document;
    URL.createObjectURL = original.create;
    URL.revokeObjectURL = original.revoke;
  });
  return { button: new Button(), anchor, blob: () => blob, revoked };
};

for (const name of ["plain", "oracle.gresource", "oracle-v3.rcc"]) {
  void test(`downloads ${name} content and restores the button and object URL`, async context => {
    const dom = installDom(context);
    const file = new MockFile(name === "plain" ? minimalRcc().bytes : embeddedResourceFixture(name));
    const analysis = await detectEmbeddedResources(file, [{ name: ".data", offset: 0, size: file.size }], []);
    assert.ok(analysis);
    dom.button.dataset["embeddedResourceEntry"] = name === "oracle-v3.rcc" ? "3" : "1";
    const handler = createEmbeddedResourceClickHandler({ getFile: () => file,
      getParseResult: () => ({ analyzer: "pe", parsed: { ...createBasePe(), embeddedResources: analysis } }),
      setStatusMessage: message => { assert.fail(String(message)); } });
    await handler({ target: dom.button } as unknown as Event);
    assert.equal(await dom.blob()?.text(), name === "plain" ? "hello" : "Binary101 resource oracle ".repeat(50));
    assert.equal(dom.anchor.download, name === "plain" ? "a" : "message.txt");
    assert.equal(dom.button.disabled, false);
    assert.deepEqual(dom.revoked, ["blob:resource"]);
  });
}

void test("ignores unrelated clicks, absent files and invalid entry indices", async context => {
  const dom = installDom(context);
  const handler = createEmbeddedResourceClickHandler({ getFile: () => null,
    getParseResult: () => ({ analyzer: null, parsed: null }), setStatusMessage: () => {} });
  await handler({ target: null } as Event);
  await handler({ target: dom.button } as unknown as Event);
  const empty = createEmbeddedResourceClickHandler({ getFile: () => null,
    getParseResult: () => ({ analyzer: "pe", parsed: createBasePe() }), setStatusMessage: () => {} });
  await empty({ target: dom.button } as unknown as Event);
  assert.equal(dom.blob(), null);
});

void test("reports failed extraction and always restores the button", async context => {
  const dom = installDom(context);
  const file = new MockFile(embeddedResourceFixture("oracle.gresource"));
  const analysis = await detectEmbeddedResources(file, [{ name: ".data", offset: 0, size: file.size }], []);
  assert.ok(analysis);
  analysis.bundles[0]!.resource.entries[1]!.payload!.uncompressedSize = 0;
  const messages: Array<string | null | undefined> = [];
  const handler = createEmbeddedResourceClickHandler({ getFile: () => file,
    getParseResult: () => ({ analyzer: "pe", parsed: { ...createBasePe(), embeddedResources: analysis } }),
    setStatusMessage: message => messages.push(message) });
  await handler({ target: dom.button } as unknown as Event);
  assert.match(messages[0]!, /Resource extraction failed/);
  assert.equal(dom.button.disabled, false);
  assert.equal(dom.blob(), null);
});

void test("downloads an unnamed entry with a safe fallback and reports non-Error failures", async context => {
  const dom = installDom(context);
  const file = new MockFile(minimalRcc().bytes);
  const analysis = await detectEmbeddedResources(file, [{ name: ".data", offset: 0, size: file.size }], []);
  assert.ok(analysis);
  analysis.bundles[0]!.resource.entries[1]!.name = "";
  const messages: Array<string | null | undefined> = [];
  const handler = createEmbeddedResourceClickHandler({ getFile: () => file,
    getParseResult: () => ({ analyzer: "pe", parsed: { ...createBasePe(), embeddedResources: analysis } }),
    setStatusMessage: message => messages.push(message) });
  await handler({ target: dom.button } as unknown as Event);
  assert.equal(dom.anchor.download, "resource.bin");
  dom.anchor.click = () => { throw "blocked"; };
  await handler({ target: dom.button } as unknown as Event);
  assert.deepEqual(messages, ["Resource extraction failed: blocked"]);
  assert.equal(dom.button.disabled, false);
  assert.deepEqual(dom.revoked, ["blob:resource", "blob:resource"]);
});

void test("ignores element clicks outside resource buttons and fileless selections", async context => {
  const dom = installDom(context);
  const file = new MockFile(minimalRcc().bytes);
  const analysis = await detectEmbeddedResources(file, [{ name: ".data", offset: 0, size: file.size }], []);
  assert.ok(analysis);
  const handler = createEmbeddedResourceClickHandler({ getFile: () => null,
    getParseResult: () => ({ analyzer: "pe", parsed: { ...createBasePe(), embeddedResources: analysis } }),
    setStatusMessage: () => {} });
  await handler({ target: dom.button } as unknown as Event);
  context.mock.method(dom.button, "closest", () => null);
  await handler({ target: dom.button } as unknown as Event);
  assert.equal(dom.blob(), null);
});
