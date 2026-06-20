"use strict";

import { createInspectionHistoryController } from "./inspection-history.js";
import type { DirectoryInspectionRoute } from "./directory-inspection.js";
import type { InspectionContext } from "./inspection-context.js";
import type { InspectionHistoryConfig } from "./inspection-history.js";

type FileRouteOpener = (file: File, context: InspectionContext) => Promise<void>;
type EmptyRouteOpener = (message: string | null) => void;
type DirectoryRouteOpener = (route: DirectoryInspectionRoute) => void;

interface InspectionNavigationConfig {
  readonly history?: InspectionHistoryConfig["history"];
  readonly targetWindow?: InspectionHistoryConfig["targetWindow"];
  readonly openDirectoryRoute: DirectoryRouteOpener;
  readonly openEmptyRoute: EmptyRouteOpener;
  readonly openFileRoute: FileRouteOpener;
}

interface InspectionNavigationController {
  initialize(): void;
  openDirectory(route: DirectoryInspectionRoute): void;
  openFile(file: File, context: InspectionContext): Promise<void>;
}

type InspectionRoute =
  | { readonly kind: "directory"; readonly directory: DirectoryInspectionRoute }
  | { readonly kind: "empty" }
  | { readonly kind: "file"; readonly file: File; readonly context: InspectionContext };

const UNAVAILABLE_ROUTE_MESSAGE =
  "History entry is no longer available. Select the file or folder again.";

const createInspectionNavigationController = (
  config: InspectionNavigationConfig
): InspectionNavigationController => {
  const routes = new Map<string, InspectionRoute>();
  let nextRouteNumber = 0;
  const storeRoute = (route: InspectionRoute): string => {
    nextRouteNumber += 1;
    const routeId = `inspection-${nextRouteNumber}`;
    routes.set(routeId, route);
    return routeId;
  };
  const openRoute = (route: InspectionRoute): void => {
    if (route.kind === "empty") {
      config.openEmptyRoute(null);
      return;
    }
    if (route.kind === "directory") {
      config.openDirectoryRoute(route.directory);
      return;
    }
    void config.openFileRoute(route.file, route.context);
  };
  const restoreRoute = (routeId: string | null): void => {
    const route = routeId ? routes.get(routeId) : null;
    if (route) {
      openRoute(route);
      return;
    }
    config.openEmptyRoute(UNAVAILABLE_ROUTE_MESSAGE);
  };
  const historyController = createInspectionHistoryController({
    ...(config.history ? { history: config.history } : {}),
    ...(config.targetWindow ? { targetWindow: config.targetWindow } : {}),
    openRoute: restoreRoute
  });
  return {
    initialize: () => historyController.initialize(storeRoute({ kind: "empty" })),
    openDirectory: route => historyController.push(storeRoute({ kind: "directory", directory: route })),
    openFile: async (file, context) => {
      historyController.push(storeRoute({ kind: "file", file, context }));
      await config.openFileRoute(file, context);
    }
  };
};

export { createInspectionNavigationController };
export type { InspectionNavigationConfig, InspectionNavigationController };
