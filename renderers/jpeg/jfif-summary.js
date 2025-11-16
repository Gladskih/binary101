"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";

function describeUnits(units) {
  if (units === 1) return "pixels per inch (dpi)";
  if (units === 2) return "pixels per centimeter (dpcm)";
  return "no absolute units (aspect ratio only)";
}

function describeDensity(x, y, units) {
  if (!x || !y) {
    return "Not specified";
  }
  const unitLabel = describeUnits(units);
  const base = `${x} × ${y} ${unitLabel}`;
  if (units === 1 || units === 2) {
    if (x === y && x >= 280 && x <= 360) {
      return `${base} — typical print/screen resolution`;
    }
    if (x === y && x <= 120) {
      return `${base} — low resolution (web / preview)`;
    }
    if (x === y && x >= 600) {
      return `${base} — very high resolution (fine print or scanning)`;
    }
  }
  return base;
}

function describeThumbnail(x, y) {
  if (!x || !y) return "No embedded thumbnail";
  return `${x} × ${y} px — small preview image embedded in the file`;
}

export function renderJfifSummary(jfif) {
  const out = [];
  const { versionMajor, versionMinor, units, xDensity, yDensity, xThumbnail, yThumbnail } =
    jfif;
  out.push("<h4>JFIF header</h4>");
  out.push("<dl>");
  const versionLabel = `${versionMajor}.${String(versionMinor).padStart(2, "0")}`;
  out.push(
    renderDefinitionRow(
      "JFIF version",
      escapeHtml(versionLabel),
      "JFIF version of the container. 1.01 and 1.02 are the most common."
    )
  );
  out.push(
    renderDefinitionRow(
      "Pixel density",
      escapeHtml(describeDensity(xDensity, yDensity, units)),
      "Pixel density is used by viewers to map image pixels to physical size on screen or paper."
    )
  );
  out.push(
    renderDefinitionRow(
      "Thumbnail",
      escapeHtml(describeThumbnail(xThumbnail, yThumbnail)),
      "Some JFIF files embed a tiny preview image that can be shown without decoding the full JPEG."
    )
  );
  out.push("</dl>");
  return out.join("");
}

