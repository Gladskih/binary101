"use strict";

import { hex } from "../../binary-utils.js";

export const renderEntrypointJumpButton = (rva: number): string =>
  `<button type="button" class="peEntrypointJump" data-pe-entrypoint-jump="${rva}">` +
  `${hex(rva, 8)}</button>`;
