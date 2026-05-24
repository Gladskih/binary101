"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createInspectionHistoryController } from "../../ui/inspection-history.js";

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
