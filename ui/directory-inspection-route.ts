"use strict";

import type { BrowserDirectoryHandle } from "./directory-handles.js";
import type { InspectionContext } from "./inspection-context.js";

interface DirectoryLocation {
  readonly handle: BrowserDirectoryHandle;
  readonly name: string;
  readonly relativePath: string;
}

interface DirectoryInspectionRoute {
  readonly context: InspectionContext;
  readonly locations: readonly DirectoryLocation[];
}

const copyDirectoryLocations = (locations: readonly DirectoryLocation[]): DirectoryLocation[] =>
  locations.map(location => ({
    handle: location.handle,
    name: location.name,
    relativePath: location.relativePath
  }));

const createDirectoryInspectionRoute = (
  context: InspectionContext,
  locations: readonly DirectoryLocation[]
): DirectoryInspectionRoute => ({ context, locations: copyDirectoryLocations(locations) });

const createRootDirectoryLocation = (
  handle: BrowserDirectoryHandle,
  context: InspectionContext
): DirectoryLocation => {
  const name = handle.name || "Selected folder";
  return { handle, name, relativePath: context.object === "directory" ? name : "" };
};

const appendRelativeDirectoryPath = (parentPath: string, childPath: string): string =>
  parentPath ? `${parentPath}/${childPath}` : childPath;

export {
  appendRelativeDirectoryPath,
  copyDirectoryLocations,
  createDirectoryInspectionRoute,
  createRootDirectoryLocation
};
export type { DirectoryInspectionRoute, DirectoryLocation };
