"use strict";

import { safe } from "../../html-utils.js";
import type { PeNativeAotCandidate } from "../../analyzers/pe/native-aot.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

export const renderNativeAotCandidate = (
  candidate: PeNativeAotCandidate | null | undefined,
  out: string[]
): void => {
  if (!candidate) return;
  out.push(renderPeSectionStart("Native AOT candidate", "conservative evidence"));
  out.push(`<p class="smallNote">${safe(candidate.note)}</p>`);
  out.push(`<ul class="smallNote">`);
  candidate.evidence.forEach(item => out.push(`<li>${safe(item)}</li>`));
  out.push(`</ul>`);
  out.push(renderPeSectionEnd());
};
