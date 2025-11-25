"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";
import {
  CHANNEL_MODE_LABEL_TO_CODE,
  CHANNEL_MODE_OPTS,
  describeAudioBytes,
  describeAudioOffset,
  describeApe,
  describeBitrate,
  describeChannelMode,
  describeDuration,
  describeId3v1,
  describeId3v2,
  describeLayer,
  describeLyrics3,
  describeMpegVersion,
  describeSampleRate,
  describeVbrFlag,
  formatBoolean,
  formatDuration,
  LAYER_LABEL_TO_CODE,
  LAYER_OPTS,
  MPEG_VERSION_LABEL_TO_CODE,
  MPEG_VERSION_OPTS,
  renderEnumChips,
  valueWithHint,
  withFieldNote
} from "./formatting.js";
import type { Mp3SuccessResult } from "../../analyzers/mp3/types.js";

export function renderSummary(mp3: Mp3SuccessResult | null | unknown): string {
  const data = mp3 as Mp3SuccessResult | null;
  const { summary, audioDataBytes } = data || {};
  if (!summary) return "";
  const rows = [];
  const versionCode = MPEG_VERSION_LABEL_TO_CODE.get(summary.mpegVersion || "");
  const layerCode = LAYER_LABEL_TO_CODE.get(summary.layer || "");
  const channelCode = CHANNEL_MODE_LABEL_TO_CODE.get(summary.channelMode || "");
  rows.push(
    renderDefinitionRow(
      "MPEG version",
      withFieldNote(
        valueWithHint(
          versionCode != null
            ? renderEnumChips(versionCode, MPEG_VERSION_OPTS)
            : escapeHtml(summary.mpegVersion || "Unknown"),
          describeMpegVersion(summary.mpegVersion)
        ),
        "MPEG audio profile family (v1 high-rate; v2/v2.5 low-rate)."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Layer",
      withFieldNote(
        valueWithHint(
          layerCode != null
            ? renderEnumChips(layerCode, LAYER_OPTS)
            : escapeHtml(summary.layer || "Unknown"),
          describeLayer(summary.layer)
        ),
        "Layer chooses the codec flavor; Layer III is MP3 (not a quality tier)."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Channel mode",
      withFieldNote(
        valueWithHint(
          channelCode != null
            ? renderEnumChips(channelCode, CHANNEL_MODE_OPTS)
            : escapeHtml(summary.channelMode || "Unknown"),
          describeChannelMode(summary.channelMode)
        ),
        "Channel layouts in MP3 are limited to these stereo/mono options; surround (5.1) is not supported."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Sample rate",
      withFieldNote(
        valueWithHint(
          summary.sampleRateHz ? `${summary.sampleRateHz} Hz` : "Unknown",
          describeSampleRate(summary.sampleRateHz)
        ),
        "Sample rate from MPEG header (table-limited per version)."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Average bitrate",
      withFieldNote(
        valueWithHint(
          summary.bitrateKbps ? `${summary.bitrateKbps} kbps` : "Unknown",
          describeBitrate(summary.bitrateKbps, summary.isVbr)
        ),
        "Bitrate comes from the MPEG table (preset steps only; e.g., 32–320 kbps for v1 Layer III)."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Duration",
      withFieldNote(
        valueWithHint(formatDuration(summary.durationSeconds), describeDuration(summary.durationSeconds)),
        "Estimated from VBR header, frame count, or bitrate."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Audio payload offset",
      withFieldNote(
        valueWithHint(
          summary.audioDataOffset != null ? `${summary.audioDataOffset} B` : "Unknown",
          describeAudioOffset(summary.audioDataOffset)
        ),
        "Byte offset of the first MPEG frame (metadata before it pushes audio back)."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Estimated audio bytes",
      withFieldNote(
        valueWithHint(audioDataBytes ? formatHumanSize(audioDataBytes) : "Unknown", describeAudioBytes(audioDataBytes)),
        "Approximate MPEG audio payload (excludes leading/trailing tags)."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "VBR",
      withFieldNote(
        valueWithHint(formatBoolean(summary.isVbr), describeVbrFlag(summary.isVbr)),
        "Variable vs constant bitrate flag."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "ID3v2 tag",
      withFieldNote(
        valueWithHint(formatBoolean(summary.hasId3v2), describeId3v2(summary.hasId3v2)),
        "Modern metadata tag at file start (cover art, text frames)."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "ID3v1 tag",
      withFieldNote(
        valueWithHint(formatBoolean(summary.hasId3v1), describeId3v1(summary.hasId3v1)),
        "Legacy 128-byte trailer with plain text fields."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "APE tag",
      withFieldNote(
        valueWithHint(formatBoolean(summary.hasApeTag), describeApe(summary.hasApeTag)),
        "Optional metadata/ReplayGain block (uncommon in MP3)."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Lyrics3 tag",
      withFieldNote(
        valueWithHint(formatBoolean(summary.hasLyrics3), describeLyrics3(summary.hasLyrics3)),
        "Optional lyrics tag stored near the end of the file (rare)."
      )
    )
  );
  return "<h4>Summary</h4><dl>" + rows.join("") + "</dl>";
}
