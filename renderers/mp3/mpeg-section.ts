"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";
import { formatBoolean, valueWithHint, withFieldNote } from "./formatting.js";
import type { Mp3SuccessResult, MpegFrameHeader } from "../../analyzers/mp3/types.js";

function describeFrameOffset(offset: number): string {
  return offset === 0
    ? "First MPEG frame starts at the beginning of the file."
    : `${offset} B offset - audio begins after tags or padding.`;
}

function describeFrameLength(length: number | null | undefined): string {
  if (!length) {
    return "Frame length could not be computed from the header fields.";
  }
  if (length < 200) return `${length} B per frame - extremely small, typical of very low bitrate audio.`;
  if (length < 500) return `${length} B per frame - small frame size; low bitrate or short samples.`;
  if (length < 1500) return `${length} B per frame - typical MP3 frame size for music.`;
  return `${length} B per frame - unusually large; check for parsing issues or very high bitrates.`;
}

function describeSamplesPerFrame(samples: number | null | undefined): string {
  if (!samples) return "Number of PCM samples carried by one MPEG frame.";
  if (samples === 1152) return "1152 samples per frame - standard for MPEG1 Layer III (common).";
  if (samples === 576) return "576 samples per frame - short blocks for MPEG2/2.5 Layer III (low bitrate mode).";
  if (samples === 384) return "384 samples per frame - typical of Layer I (rare in MP3 files).";
  return `${samples} samples per frame from header.`;
}

function describeCrc(hasCrc: boolean | null | undefined): string {
  if (hasCrc) {
    return "CRC16 present: decoder can verify frame integrity; rarely used because it costs extra bits.";
  }
  return "No CRC (most encoders default to this to save bits).";
}

function describePadding(padding: boolean | null | undefined): string {
  if (padding) {
    return "Padding bit set - occasional extra slot to keep constant bitrate timing; normal for some bitrates.";
  }
  return "No padding on this frame - also normal; encoders toggle this to maintain timing.";
}

function describePrivateBit(privateBit: boolean | null | undefined): string {
  if (privateBit) {
    return "Private bit is set; reserved for encoder-specific flags (rarely used by players).";
  }
  return "Private bit clear - common default; field is free for encoder use.";
}

function describeCopyright(copyright: boolean | null | undefined): string {
  if (copyright) {
    return "Copyright bit set - indicates protected content; seldom relied on by players.";
  }
  return "Copyright bit clear - common default for user-encoded files.";
}

function describeOriginal(original: boolean | null | undefined): string {
  if (original) {
    return "Original bit set - marked as an original stream (common for encoder output).";
  }
  return "Original bit clear - marked as a copy; uncommon.";
}

function describeModeExtension(
  modeExtension: string | null | undefined,
  channelMode: string | null | undefined
): string {
  if (!modeExtension) {
    return "Mode extension applies only to Joint stereo; intensity/MS stereo choices help save bitrate.";
  }
  const base = `${modeExtension} - stereo coding tool used when channel mode is ${channelMode};`;
  return `${base} MS stereo is the popular option.`;
}

function describeEmphasis(emphasis: string | null | undefined): string {
  if (!emphasis) return "Emphasis flag requests de-emphasis EQ on playback; rarely used today.";
  if (emphasis === "None") return "No emphasis (default/typical).";
  return `${emphasis} emphasis - legacy feature, rare to see in modern files.`;
}

function describeSecondFrame(validated: boolean | null | undefined): string {
  if (validated === true) {
    return "Second frame header matches the first one; suggests a consistent stream.";
  }
  if (validated === false) {
    return "Expected a second frame but it did not match; file may be truncated or header may be a false sync.";
  }
  return "Second frame could not be checked.";
}

function describeNonAudioBytes(nonAudioBytes: number | null | undefined): string {
  if (nonAudioBytes == null) return "Bytes outside MPEG frames (front tags + trailing tags/junk).";
  if (nonAudioBytes === 0) return "No non-audio padding detected after the first frame.";
  if (nonAudioBytes < 1000) return `${formatHumanSize(nonAudioBytes)} of non-audio data - small tags or padding.`;
  if (nonAudioBytes < 2_000_000) {
    return `${formatHumanSize(nonAudioBytes)} of non-audio data - likely tags or embedded cover art (common).`;
  }
  return `${formatHumanSize(nonAudioBytes)} of non-audio data - unusually large; may contain bundled files or junk.`;
}

function renderFrameLayoutRows(frame: MpegFrameHeader): string[] {
  return [
    renderDefinitionRow(
      "Frame offset",
      withFieldNote(
        valueWithHint(`${frame.offset} B`, describeFrameOffset(frame.offset)),
        "Position of the first MPEG frame relative to file start."
      )
    ),
    renderDefinitionRow(
      "Frame length",
      withFieldNote(
        valueWithHint(
          frame.frameLengthBytes ? `${frame.frameLengthBytes} B` : "Unknown",
          describeFrameLength(frame.frameLengthBytes)
        ),
        "Size of the first MPEG frame in bytes."
      )
    ),
    renderDefinitionRow(
      "Samples per frame",
      withFieldNote(
        valueWithHint(
          frame.samplesPerFrame != null ? `${frame.samplesPerFrame}` : "Unknown",
          describeSamplesPerFrame(frame.samplesPerFrame)
        ),
        "PCM samples carried by one frame."
      )
    )
  ];
}

function renderFrameFlagRows(frame: MpegFrameHeader): string[] {
  return [
    renderDefinitionRow(
      "CRC present",
      withFieldNote(
        valueWithHint(formatBoolean(frame.hasCrc), describeCrc(frame.hasCrc)),
        "CRC16 checksum bit for this frame."
      )
    ),
    renderDefinitionRow(
      "Padding",
      withFieldNote(
        valueWithHint(formatBoolean(frame.padding), describePadding(frame.padding)),
        "Padding bit toggles extra slot to keep constant bitrate timing."
      )
    ),
    renderDefinitionRow(
      "Private bit",
      withFieldNote(
        valueWithHint(formatBoolean(frame.privateBit), describePrivateBit(frame.privateBit)),
        "Reserved encoder-specific flag."
      )
    ),
    renderDefinitionRow(
      "Copyright",
      withFieldNote(
        valueWithHint(formatBoolean(frame.copyright), describeCopyright(frame.copyright)),
        "Copyright flag from header."
      )
    ),
    renderDefinitionRow(
      "Original",
      withFieldNote(
        valueWithHint(formatBoolean(frame.original), describeOriginal(frame.original)),
        "Marks stream as original vs copy."
      )
    )
  ];
}

function renderStereoRows(frame: MpegFrameHeader): string[] {
  const rows: string[] = [];
  if (frame.modeExtension) {
    rows.push(
      renderDefinitionRow(
        "Mode extension",
        withFieldNote(
          valueWithHint(
            escapeHtml(frame.modeExtension),
            describeModeExtension(frame.modeExtension, frame.channelMode)
          ),
          "Stereo coding tools used only when channel mode is Joint stereo."
        )
      )
    );
  }
  if (frame.emphasis && frame.emphasis !== "None") {
    rows.push(
      renderDefinitionRow(
        "Emphasis",
        withFieldNote(
          valueWithHint(escapeHtml(frame.emphasis), describeEmphasis(frame.emphasis)),
          "Playback de-emphasis request (legacy)."
        )
      )
    );
  }
  return rows;
}

function renderStreamValidationRows(mpeg: Mp3SuccessResult["mpeg"]): string[] {
  const rows: string[] = [];
  if (mpeg.secondFrameValidated === false) {
    rows.push(
      renderDefinitionRow(
        "Second frame",
        withFieldNote(
          valueWithHint("Validation failed", describeSecondFrame(false)),
          "Checks if the next frame matches header expectations."
        )
      )
    );
  } else if (mpeg.secondFrameValidated === true) {
    rows.push(
      renderDefinitionRow(
        "Second frame",
        withFieldNote(
          valueWithHint("Validated", describeSecondFrame(true)),
          "Checks if the next frame matches header expectations."
        )
      )
    );
  }
  return rows;
}

export function renderMpeg(mpeg: Mp3SuccessResult["mpeg"] | null | undefined): string {
  if (!mpeg || !mpeg.firstFrame) return "";
  const rows = [
    ...renderFrameLayoutRows(mpeg.firstFrame),
    ...renderFrameFlagRows(mpeg.firstFrame),
    ...renderStereoRows(mpeg.firstFrame),
    ...renderStreamValidationRows(mpeg)
  ];
  if (mpeg.nonAudioBytes != null) {
    rows.push(
      renderDefinitionRow(
        "Non-audio bytes",
        withFieldNote(
          valueWithHint(formatHumanSize(mpeg.nonAudioBytes), describeNonAudioBytes(mpeg.nonAudioBytes)),
          "Bytes outside MPEG frames (leading/trailing tags or junk)."
        )
      )
    );
  }
  return "<h4>MPEG audio stream</h4><dl>" + rows.join("") + "</dl>";
}
