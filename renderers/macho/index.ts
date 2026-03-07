"use strict";

import { safe } from "../../html-utils.js";
import type { MachOParseResult } from "../../analyzers/macho/types.js";
import { renderFat } from "./fat-view.js";
import { renderImage } from "./image-view.js";

const renderIssues = (issues: string[]): string => {
  if (!issues.length) return "";
  const items = issues.map(issue => `<li>${safe(issue)}</li>`).join("");
  return `<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4><ul>${items}</ul></section>`;
};

export function renderMachO(result: MachOParseResult | null): string {
  if (!result) return "";
  if (result.kind === "fat") return renderFat(result) + renderIssues(result.issues);
  if (result.kind === "thin" && result.image) return renderImage(result.image);
  return "";
}
