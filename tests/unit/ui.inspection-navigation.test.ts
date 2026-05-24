"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createInspectionNavigationController } from "../../ui/inspection-navigation.js";
import type { DirectoryInspectionRoute } from "../../ui/directory-inspection.js";
import type { BrowserDirectoryHandle } from "../../ui/directory-handles.js";

class FakeHistory {
  state: unknown = null;
  readonly pushedStates: unknown[] = [];
  readonly replacedStates: unknown[] = [];
  pushState(data: unknown): void {
    this.state = data;
    this.pushedStates.push(data);
  }
  replaceState(data: unknown): void {
    this.state = data;
    this.replacedStates.push(data);
  }
}

class FakeWindow {
  readonly popstateListeners: Array<(event: PopStateEvent) => void> = [];
  addEventListener(name: "popstate", listener: (event: PopStateEvent) => void): void {
    assert.equal(name, "popstate");
    this.popstateListeners.push(listener);
  }
  dispatchPopState(state: unknown): void {
    this.popstateListeners.forEach(listener => listener({ state } as PopStateEvent));
  }
}

const createDirectoryRoute = (displayPath: string): DirectoryInspectionRoute => ({
  locations: [{ displayPath, handle: createDirectoryHandle(displayPath) }],
  sourceDescription: "Folder"
});

const createDirectoryHandle = (name: string): BrowserDirectoryHandle => ({
  kind: "directory",
  name,
  async *entries() {}
});

void test("inspection navigation pushes directory and file routes", async () => {
  const history = new FakeHistory();
  const targetWindow = new FakeWindow();
  const openedFiles: string[] = [];
  const navigation = createInspectionNavigationController({
    history,
    targetWindow,
    openDirectoryRoute: () => undefined,
    openEmptyRoute: () => undefined,
    openFileRoute: async file => { openedFiles.push(file.name); }
  });
  navigation.initialize();
  navigation.openDirectory(createDirectoryRoute("root"));
  await navigation.openFile(new File(["a"], "alpha.txt"), "File selection");
  assert.equal(openedFiles[0], "alpha.txt");
  assert.deepEqual(history.replacedStates, [{ app: "binary101", routeId: "inspection-1", version: 1 }]);
  assert.deepEqual(history.pushedStates, [
    { app: "binary101", routeId: "inspection-2", version: 1 },
    { app: "binary101", routeId: "inspection-3", version: 1 }
  ]);
});

void test("inspection navigation restores routes from browser history", () => {
  const history = new FakeHistory();
  const targetWindow = new FakeWindow();
  const openedDirectories: string[] = [];
  const emptyMessages: Array<string | null> = [];
  const navigation = createInspectionNavigationController({
    history,
    targetWindow,
    openDirectoryRoute: route => openedDirectories.push(route.locations[0]?.displayPath ?? ""),
    openEmptyRoute: message => emptyMessages.push(message),
    openFileRoute: async () => undefined
  });
  navigation.initialize();
  navigation.openDirectory(createDirectoryRoute("root"));
  targetWindow.dispatchPopState(history.pushedStates[0]);
  targetWindow.dispatchPopState({ app: "binary101", routeId: "missing", version: 1 });
  assert.deepEqual(openedDirectories, ["root"]);
  assert.deepEqual(emptyMessages, ["History entry is no longer available. Select the file or folder again."]);
});
