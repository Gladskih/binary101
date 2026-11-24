import type { PeResources } from "../../analyzers/pe/resources/index.js";

export const hasPeResourceDirectoryDetails = (resources: PeResources | null): boolean =>
  Boolean(resources && (resources.directories?.length || resources.top.length ||
    resources.detail.length || resources.paths?.length));
