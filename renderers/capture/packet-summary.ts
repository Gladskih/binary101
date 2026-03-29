"use strict";

import { formatHumanSize } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type { PcapPacketStats } from "../../analyzers/capture/types.js";

// SI time unit conversions used for display formatting.
const MILLISECONDS_PER_SECOND = 1000;
const MICROSECONDS_PER_SECOND = 1_000_000;
const SECONDS_PER_MINUTE = 60;

const formatTimestampSeconds = (seconds: number | null | undefined): string => {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds <= 0) return "-";

  const iso = new Date(seconds * MILLISECONDS_PER_SECOND).toISOString();
  const rounded =
    Math.round(seconds * MICROSECONDS_PER_SECOND) / MICROSECONDS_PER_SECOND;
  return `${escapeHtml(iso)} (${escapeHtml(`${rounded}`)} s)`;
};

const formatDurationSeconds = (seconds: number | null | undefined): string => {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return "Unknown";
  // Local UI policy: sub-millisecond durations are easier to scan in microseconds.
  if (seconds < 0.001) {
    return `${Math.round(seconds * MICROSECONDS_PER_SECOND)} us`;
  }
  if (seconds < 1) return `${Math.round(seconds * MILLISECONDS_PER_SECOND)} ms`;
  // Local UI policy: keep millisecond precision only for short sub-10-second spans.
  if (seconds < 10) {
    return `${Math.round(seconds * MILLISECONDS_PER_SECOND) / MILLISECONDS_PER_SECOND} s`;
  }
  // Local UI policy: keep one decimal place until the duration reaches ten minutes.
  if (seconds < 600) return `${Math.round(seconds * 10) / 10} s`;

  const minutes = Math.floor(seconds / SECONDS_PER_MINUTE);
  const remaining = Math.round(seconds - minutes * SECONDS_PER_MINUTE);
  return `${minutes} min ${remaining} s`;
};

export const renderPacketSummary = (packets: PcapPacketStats, out: string[]): void => {
  out.push("<h4>Packets</h4><dl>");
  out.push(renderDefinitionRow("Total packets", escapeHtml(`${packets.totalPackets}`)));
  out.push(
    renderDefinitionRow(
      "Total captured bytes",
      escapeHtml(formatHumanSize(packets.totalCapturedBytes))
    )
  );
  out.push(
    renderDefinitionRow(
      "Total original bytes",
      escapeHtml(formatHumanSize(packets.totalOriginalBytes))
    )
  );
  out.push(
    renderDefinitionRow(
      "Capture length (min/avg/max)",
      packets.capturedLengthMin != null &&
      packets.capturedLengthMax != null &&
      packets.capturedLengthAverage != null
        ? escapeHtml(
            `${packets.capturedLengthMin} / ${packets.capturedLengthAverage} / ${packets.capturedLengthMax}`
          )
        : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow(
      "Original length (min/avg/max)",
      packets.originalLengthMin != null &&
      packets.originalLengthMax != null &&
      packets.originalLengthAverage != null
        ? escapeHtml(
            `${packets.originalLengthMin} / ${packets.originalLengthAverage} / ${packets.originalLengthMax}`
          )
        : "Unknown"
    )
  );
  out.push(
    renderDefinitionRow("Capture-truncated packets", escapeHtml(`${packets.truncatedPackets}`))
  );
  out.push(renderDefinitionRow("File truncated", escapeHtml(packets.truncatedFile ? "Yes" : "No")));
  if (packets.timestampMinSeconds != null || packets.timestampMaxSeconds != null) {
    out.push(renderDefinitionRow("Time start", formatTimestampSeconds(packets.timestampMinSeconds)));
    out.push(renderDefinitionRow("Time end", formatTimestampSeconds(packets.timestampMaxSeconds)));
    const duration =
      packets.timestampMinSeconds != null && packets.timestampMaxSeconds != null
        ? packets.timestampMaxSeconds - packets.timestampMinSeconds
        : null;
    out.push(renderDefinitionRow("Time span", escapeHtml(formatDurationSeconds(duration))));
    out.push(
      renderDefinitionRow(
        "Out-of-order timestamps",
        escapeHtml(`${packets.outOfOrderTimestamps}`)
      )
    );
  }
  out.push("</dl>");
};
