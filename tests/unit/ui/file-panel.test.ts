import assert from "node:assert/strict";
import { test } from "node:test";
import { attachFilePanelControls } from "../../../ui/file-panel.js";

const fixture = () => {
  const elements = new Map<string, HTMLElement>();
  const listeners = new Map<string, EventListener>();
  const attributes = new Map<string, string>();
  let focusOptions: FocusOptions | undefined;
  for (const id of ["fileInfoRail", "filePanelToggle", "filePanelSearch", "workspaceFilter"]) {
    // Only the DOM surfaces used by this controller are needed in the fixture.
    const element = { dataset: {}, title: "", textContent: "saved query" } as HTMLElement;
    element.addEventListener = (type: string, listener: EventListenerOrEventListenerObject | null) => {
      assert.equal(type, "click");
      assert.equal(typeof listener, "function");
      if (typeof listener === "function") listeners.set(id, listener);
    };
    element.setAttribute = (name, value) => { attributes.set(`${id}:${name}`, value); };
    element.focus = options => { focusOptions = options; };
    elements.set(id, element);
  }
  const element = (id: string): HTMLElement => elements.get(id)!;
  return { root: { getElementById: element } as Document, element, attributes,
    click: (id: string) => listeners.get(id)!(new Event("click")), focus: () => focusOptions };
};

void test("file panel starts expanded and its toggle reports both visibility states", () => {
  const state = fixture();

  attachFilePanelControls(state.root);

  assert.equal(state.attributes.get("filePanelToggle:aria-expanded"), "true");
  assert.equal(state.attributes.get("filePanelToggle:aria-label"), "Hide file panel");
  assert.equal(state.element("filePanelToggle").title, "Hide file panel");
  state.click("filePanelToggle");
  assert.equal(state.element("fileInfoRail").dataset["collapsed"], "true");
  assert.equal(state.attributes.get("filePanelToggle:aria-expanded"), "false");
  assert.equal(state.attributes.get("filePanelToggle:aria-label"), "Show file panel");
  assert.equal(state.element("filePanelToggle").title, "Show file panel");
  state.click("filePanelToggle");
  assert.equal(state.element("fileInfoRail").dataset["collapsed"], undefined);
  assert.equal(state.attributes.get("filePanelToggle:aria-expanded"), "true");
});

void test("search expands the panel and focuses the same input without clearing its value", () => {
  const state = fixture();
  attachFilePanelControls(state.root);
  state.click("filePanelToggle");

  state.click("filePanelSearch");

  assert.equal(state.element("fileInfoRail").dataset["collapsed"], undefined);
  assert.equal(state.attributes.get("filePanelToggle:aria-expanded"), "true");
  assert.deepEqual(state.focus(), { preventScroll: true });
  assert.equal(state.element("workspaceFilter").textContent, "saved query");
});
