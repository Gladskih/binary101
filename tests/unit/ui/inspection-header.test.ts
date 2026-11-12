import assert from "node:assert/strict";
import { test } from "node:test";
import { syncInspectionHeader } from "../../../ui/inspection-header.js";

const fixture = () => {
  const parents = new Map<Node, HTMLElement>();
  const classes = new Set<string>();
  let appends = 0;
  const elements = new Map<string, HTMLElement>();
  for (const id of ["fileInfoCard", "directoryInfoCard", "fileDetails", "inspectionWorkspace",
    "fileActions", "fileChromeDock", "appHeader", "fileHeader", "workspaceSearchHome",
    "workspaceSearch", "fileNameDetail", "directoryName", "fileInfoRail", "fileIconWrap", "fileOverviewIcon"]) {
    // The fixture implements only the DOM surface exercised by header placement.
    const element = { hidden: false, textContent: "" } as HTMLElement;
    Object.defineProperty(element, "parentElement", { get: () => parents.get(element) ?? null });
    element.append = (...children) => {
      for (const child of children) {
        if (typeof child === "string") throw new Error("Expected an element");
        for (let ancestor: Node | undefined = element; ancestor; ancestor = parents.get(ancestor)) {
          if (ancestor === child) throw new Error("DOM hierarchy cycle");
        }
        parents.set(child, element);
        appends++;
      }
    };
    elements.set(id, element);
  }
  const element = (id: string): HTMLElement => elements.get(id)!;
  const root = { title: "Inspector", getElementById: element, body: { classList: {
    toggle: (name: string, force?: boolean) => {
      if (force) classes.add(name); else classes.delete(name);
      return Boolean(force);
    }
  } } } as Document;
  element("directoryInfoCard").hidden = true;
  element("fileNameDetail").textContent = "sample.exe";
  element("directoryName").textContent = "sample folder";
  const details = element("fileDetails") as HTMLDetailsElement;
  details.open = true;
  parents.set(details, element("fileInfoRail"));
  parents.set(element("fileHeader"), element("appHeader"));
  parents.set(element("fileActions"), element("appHeader"));
  parents.set(element("workspaceSearch"), element("workspaceSearchHome"));
  return { root, element, details, classes, layout: { matches: true }, appends: () => appends };
};

void test("a wide open details pane owns file identity, actions and report search", () => {
  const state = fixture();

  syncInspectionHeader(state.root, "Inspector", state.layout);

  assert.equal(state.element("fileHeader").parentElement, state.element("fileChromeDock"));
  assert.equal(state.element("fileActions").parentElement, state.element("fileChromeDock"));
  assert.equal(state.element("workspaceSearch").parentElement, state.element("fileChromeDock"));
  assert.equal(state.classes.has("hasDockedHeader"), true);
  assert.equal(state.classes.has("hasInspection"), true);
  assert.equal(state.root.title, "sample.exe — Inspector");
  const count = state.appends();
  syncInspectionHeader(state.root, "Inspector", state.layout);
  assert.equal(state.appends(), count);
});

void test("closing file properties keeps identity, actions and search accessible outside them", () => {
  const state = fixture();
  syncInspectionHeader(state.root, "Inspector", state.layout);
  state.details.open = false;

  syncInspectionHeader(state.root, "Inspector", state.layout);

  assert.equal(state.element("fileHeader").parentElement, state.element("fileChromeDock"));
  assert.equal(state.element("fileActions").parentElement, state.element("fileChromeDock"));
  assert.equal(state.element("workspaceSearch").parentElement, state.element("fileChromeDock"));
  assert.equal(state.classes.has("hasDockedHeader"), true);
});

void test("narrow details share the toolbar and can return to the dock without a hierarchy cycle", () => {
  const state = fixture();
  state.layout.matches = false;

  syncInspectionHeader(state.root, "Inspector", state.layout);

  assert.equal(state.details.parentElement, state.element("fileActions"));
  assert.equal(state.element("fileActions").parentElement, state.element("appHeader"));
  state.layout.matches = true;
  syncInspectionHeader(state.root, "Inspector", state.layout);
  assert.equal(state.details.parentElement, state.element("fileInfoRail"));
  assert.equal(state.element("fileActions").parentElement, state.element("fileChromeDock"));
  state.layout.matches = false;
  syncInspectionHeader(state.root, "Inspector", state.layout);
  assert.equal(state.element("fileActions").parentElement, state.element("appHeader"));
});

void test("directory and welcome views restore global actions and hide file properties", () => {
  const state = fixture();
  syncInspectionHeader(state.root, "Inspector", state.layout);
  state.element("fileInfoCard").hidden = true;
  state.element("directoryInfoCard").hidden = false;

  syncInspectionHeader(state.root, "Inspector", state.layout);

  assert.equal(state.root.title, "sample folder — Inspector");
  assert.equal(state.details.hidden, true);
  assert.equal(state.element("fileActions").parentElement, state.element("appHeader"));
  state.element("directoryInfoCard").hidden = true;
  syncInspectionHeader(state.root, "Inspector", state.layout);
  assert.equal(state.root.title, "Inspector");
  assert.equal(state.classes.has("hasInspection"), false);
});

void test("an unnamed file retains the application title", () => {
  const state = fixture();
  state.element("fileNameDetail").textContent = "";

  syncInspectionHeader(state.root, "Inspector", state.layout);

  assert.equal(state.root.title, "Inspector");
});
