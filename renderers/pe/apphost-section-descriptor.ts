"use strict";

import type { PeAppHostAnalysis } from "../../analyzers/pe/apphost/types.js";

export const getPeAppHostSectionDescriptor = (
  appHost: PeAppHostAnalysis
): { key: "apphost"; summary: string; title: ".NET apphost" } => ({
  key: "apphost",
  summary: appHost.locators.some(locator => (locator.bundleHeaderOffset ?? 0n) > 0n)
    ? "single-file bundle"
    : "native .NET launcher",
  title: ".NET apphost"
});
