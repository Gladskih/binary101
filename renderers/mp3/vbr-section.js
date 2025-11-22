"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { valueWithHint, withFieldNote } from "./formatting.js";

function describeVbrHeaderType(type) {
  if (!type) return "VBR headers (Xing/Info/VBRI) advertise frames/bytes for accurate duration.";
  if (type === "Xing") return "Xing header - signals VBR and may include a seek table; common with LAME encodes.";
  if (type === "Info") return "Info header - like Xing but for CBR streams; common when LAME writes encoder metadata.";
  if (type === "VBRI") return "VBRI header from old Fraunhofer encoders; rarer but valid VBR indicator.";
  return `${type} header reported in the first frame.`;
}

function describeVbrFrames(frames) {
  if (frames == null) return "Total frames reported by the VBR header; used for precise duration.";
  if (frames < 10) return `${frames} frames - extremely short snippet.`;
  if (frames < 1000) return `${frames} frames - short clip length.`;
  return `${frames} frames - typical or long track; count improves seek accuracy.`;
}

function describeVbrBytes(bytes) {
  if (bytes == null) return "Total bytes reported by the VBR header; helps check file completeness.";
  return `${bytes} bytes reported by VBR header; should roughly match audio payload size.`;
}

function describeVbrQuality(quality) {
  if (quality == null) return "Quality score from the VBR header (0 = best, 100 = worst) when provided by encoder.";
  return `${quality} (0 best, 100 worst) - encoder-provided quality hint; lower is better.`;
}

function describeLameEncoder(name) {
  if (!name) return "Encoder string from the LAME tag when present.";
  return `${name} encoder string - helpful for spotting default/popular encoders (LAME, GOGO, etc.).`;
}

export function renderVbr(vbr) {
  if (!vbr) return "";
  const rows = [];
  rows.push(
    renderDefinitionRow(
      "Header",
      withFieldNote(
        valueWithHint(escapeHtml(vbr.type), describeVbrHeaderType(vbr.type)),
        "VBR header type parsed from the first frame."
      )
    )
  );
  if (vbr.frames != null) {
    rows.push(
      renderDefinitionRow(
        "Total frames",
        withFieldNote(
          valueWithHint(String(vbr.frames), describeVbrFrames(vbr.frames)),
          "Frame count reported by VBR header (used for precise duration)."
        )
      )
    );
  }
  if (vbr.bytes != null) {
    rows.push(
      renderDefinitionRow(
        "Total bytes",
        withFieldNote(
          valueWithHint(String(vbr.bytes), describeVbrBytes(vbr.bytes)),
          "Total bytes reported by VBR header."
        )
      )
    );
  }
  if (vbr.quality != null) {
    rows.push(
      renderDefinitionRow(
        "Quality",
        withFieldNote(
          valueWithHint(String(vbr.quality), describeVbrQuality(vbr.quality)),
          "Encoder-reported quality hint (0 best, 100 worst)."
        )
      )
    );
  }
  if (vbr.lameEncoder) {
    rows.push(
      renderDefinitionRow(
        "Encoder",
        withFieldNote(
          valueWithHint(escapeHtml(vbr.lameEncoder), describeLameEncoder(vbr.lameEncoder)),
          "Encoder string from LAME/VBR header."
        )
      )
    );
  }
  return "<h4>VBR info</h4><dl>" + rows.join("") + "</dl>";
}
