"use strict";

import type { ResourcePreviewResult } from "./types.js";

const failureResult = (error: unknown): ResourcePreviewResult => {
  const message = error instanceof Error ? error.message : String(error);
  return { issues: [`Preview failed: ${message}`] };
};

export const runSyncPreviewDecoder = (
  fn: () => ResourcePreviewResult | null
): ResourcePreviewResult | null => {
  try {
    return fn();
  } catch (error) {
    return failureResult(error);
  }
};

export const runAsyncPreviewDecoder = async (
  fn: () => Promise<ResourcePreviewResult | null>
): Promise<ResourcePreviewResult | null> => {
  try {
    return await fn();
  } catch (error) {
    return failureResult(error);
  }
};
