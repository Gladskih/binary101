"use strict";

interface BrowserHistoryLike {
  readonly state: unknown;
  pushState(data: unknown, unused: string): void;
  replaceState(data: unknown, unused: string): void;
}

interface BrowserWindowLike {
  addEventListener(name: "popstate", listener: (event: PopStateEvent) => void): void;
}

interface InspectionHistoryConfig {
  readonly history?: BrowserHistoryLike;
  readonly targetWindow?: BrowserWindowLike;
  readonly openRoute: (routeId: string | null) => void;
  readonly openSection?: (key: string | null) => void;
}

interface InspectionHistoryController {
  currentRouteId(): string | null;
  initialize(routeId: string): void;
  push(routeId: string): void;
  replace(routeId: string): void;
  currentSectionKey(): string | null;
  initializeSection(key: string): void;
  selectSection(key: string): void;
}

interface InspectionHistoryState {
  readonly app: "binary101";
  readonly routeId: string;
  readonly version: 1;
  readonly section?: string;
}

const createInspectionHistoryState = (routeId: string): InspectionHistoryState => ({
  app: "binary101",
  routeId,
  version: 1
});

const readInspectionRouteId = (state: unknown): string | null => {
  if (!state || typeof state !== "object") return null;
  const candidate = state as Partial<InspectionHistoryState>;
  if (candidate.app !== "binary101" || candidate.version !== 1) return null;
  return typeof candidate.routeId === "string" ? candidate.routeId : null;
};

const readSectionKey = (state: unknown): string | null => {
  if (!readInspectionRouteId(state)) return null;
  const candidate = state as InspectionHistoryState;
  return typeof candidate.section === "string" ? candidate.section : null;
};

const createInspectionHistoryController = (
  config: InspectionHistoryConfig
): InspectionHistoryController => {
  const historyObject = config.history ?? window.history;
  const targetWindow: BrowserWindowLike = config.targetWindow ?? window;
  let activeRouteId = readInspectionRouteId(historyObject.state);
  const setActiveRouteId = (routeId: string): void => {
    activeRouteId = routeId;
  };
  const writeState = (
    routeId: string,
    writer: (state: InspectionHistoryState, unused: string) => void
  ): void => {
    setActiveRouteId(routeId);
    writer(createInspectionHistoryState(routeId), "");
  };
  const writeSection = (key: string, writer: BrowserHistoryLike["pushState"]): void => {
    if (!activeRouteId) return;
    writer({ ...createInspectionHistoryState(activeRouteId), section: key }, "");
  };
  targetWindow.addEventListener("popstate", event => {
    const routeId = readInspectionRouteId(event.state);
    if (routeId && routeId === activeRouteId && readSectionKey(event.state) !== null) {
      config.openSection?.(readSectionKey(event.state));
      return;
    }
    activeRouteId = routeId;
    config.openRoute(activeRouteId);
  });
  return {
    currentRouteId: () => activeRouteId,
    initialize: routeId => writeState(routeId, historyObject.replaceState.bind(historyObject)),
    push: routeId => writeState(routeId, historyObject.pushState.bind(historyObject)),
    replace: routeId => writeState(routeId, historyObject.replaceState.bind(historyObject)),
    currentSectionKey: () => readSectionKey(historyObject.state),
    initializeSection: key => writeSection(key, historyObject.replaceState.bind(historyObject)),
    selectSection: key => {
      if (readSectionKey(historyObject.state) !== key) {
        writeSection(key, historyObject.pushState.bind(historyObject));
      }
    }
  };
};

export { createInspectionHistoryController };
export type { InspectionHistoryConfig, InspectionHistoryController };
