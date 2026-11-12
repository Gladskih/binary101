"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createInspectionHistoryController } from "../../../ui/inspection-history.js";

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

void test("inspection history stores small route ids in browser state", () => {
  const history = new FakeHistory();
  const targetWindow = new FakeWindow();
  const openedRoutes: Array<string | null> = [];
  const controller = createInspectionHistoryController({
    history,
    targetWindow,
    openRoute: routeId => openedRoutes.push(routeId)
  });
  controller.initialize("empty");
  controller.push("folder");
  controller.replace("file");
  assert.equal(controller.currentRouteId(), "file");
  assert.deepEqual(history.replacedStates, [
    { app: "binary101", routeId: "empty", version: 1 },
    { app: "binary101", routeId: "file", version: 1 }
  ]);
  assert.deepEqual(history.pushedStates, [{ app: "binary101", routeId: "folder", version: 1 }]);
});

void test("inspection history restores known app states and ignores foreign states", () => {
  const history = new FakeHistory();
  const targetWindow = new FakeWindow();
  const openedRoutes: Array<string | null> = [];
  const controller = createInspectionHistoryController({
    history,
    targetWindow,
    openRoute: routeId => openedRoutes.push(routeId)
  });
  controller.initialize("empty");
  targetWindow.dispatchPopState({ app: "binary101", routeId: "folder", version: 1 });
  targetWindow.dispatchPopState({ app: "other", routeId: "foreign", version: 1 });
  targetWindow.dispatchPopState({ app: "binary101", routeId: 7, version: 1 });
  assert.equal(controller.currentRouteId(), null);
  assert.deepEqual(openedRoutes, ["folder", null, null]);
});

void test("section history stays within the active file route and restores without reopening it", () => {
  const history = new FakeHistory();
  const targetWindow = new FakeWindow();
  const openedRoutes: Array<string | null> = [];
  const sections: Array<string | null> = [];
  const controller = createInspectionHistoryController({ history, targetWindow,
    openRoute: route => openedRoutes.push(route), openSection: key => sections.push(key) });
  controller.initialize("file");
  controller.initializeSection("overview");
  const overview = history.state;
  controller.selectSection("headers");
  controller.selectSection("headers");

  assert.equal(controller.currentSectionKey(), "headers");
  assert.equal(history.pushedStates.length, 1);
  assert.deepEqual(history.state, { app: "binary101", routeId: "file", version: 1, section: "headers" });
  history.state = overview;
  targetWindow.dispatchPopState(overview);
  assert.deepEqual(sections, ["overview"]);
  assert.deepEqual(openedRoutes, []);
  assert.equal(controller.currentSectionKey(), "overview");
  targetWindow.dispatchPopState({ app: "binary101", routeId: "folder", version: 1 });
  assert.deepEqual(openedRoutes, ["folder"]);
});

void test("uninitialized, foreign and invalid section states do not create report routes", () => {
  const history = new FakeHistory();
  const targetWindow = new FakeWindow();
  const controller = createInspectionHistoryController({ history, targetWindow, openRoute: () => {} });

  controller.initializeSection("overview");
  controller.selectSection("headers");
  assert.equal(history.replacedStates.length, 0);
  assert.equal(history.pushedStates.length, 0);
  assert.equal(controller.currentSectionKey(), null);
  history.state = { app: "other", routeId: "file", version: 1, section: "headers" };
  assert.equal(controller.currentSectionKey(), null);
  controller.initialize("file");
  history.state = { app: "binary101", routeId: "file", version: 1, section: 7 };
  assert.equal(controller.currentSectionKey(), null);
  targetWindow.dispatchPopState(history.state);
});
