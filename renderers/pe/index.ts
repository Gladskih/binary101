// @ts-nocheck
"use strict";

import { renderHeaders } from "./headers.js";
import {
  renderLoadConfig,
  renderDebug,
  renderImports,
  renderExports,
  renderTls,
  renderClr,
  renderSecurity,
  renderIat
} from "./directories.js";
import { renderResources } from "./resources.js";
import {
  renderReloc,
  renderException,
  renderBoundImports,
  renderDelayImports,
  renderCoverage,
  renderSanity
} from "./layout.js";

export function renderPe(pe) {
  if (!pe) return "";
  const out = [];
  renderHeaders(pe, out);
  renderLoadConfig(pe, out);
  renderDebug(pe, out);
  renderImports(pe, out);
  renderResources(pe, out);
  renderExports(pe, out);
  renderTls(pe, out);
  renderReloc(pe, out);
  renderException(pe, out);
  renderBoundImports(pe, out);
  renderDelayImports(pe, out);
  renderClr(pe, out);
  renderSecurity(pe, out);
  renderCoverage(pe, out);
  renderIat(pe, out);
  renderSanity(pe, out);
  return out.join("");
}
