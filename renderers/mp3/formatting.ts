// @ts-nocheck
"use strict";

import { escapeHtml } from "../../html-utils.js";

export const MPEG_VERSION_OPTS = [
  { code: 0x3, label: "MPEG Version 1", hint: "High sample-rate profile (44.1/48 kHz); common default." },
  { code: 0x2, label: "MPEG Version 2", hint: "Half-rate profile (22/24/16 kHz); lower-bitrate mode." },
  { code: 0x0, label: "MPEG Version 2.5", hint: "Low-rate extension (11/12/8 kHz); rare outside voice/streaming." }
];

export const LAYER_OPTS = [
  { code: 0x3, label: "Layer I", hint: "Earliest MPEG audio layer; rare in MP3 files." },
  { code: 0x2, label: "Layer II", hint: "MP2 broadcast-style audio; uncommon inside .mp3 files." },
  { code: 0x1, label: "Layer III", hint: "MP3 codec; dominant/default for consumer audio." }
];

export const CHANNEL_MODE_OPTS = [
  { code: 0x0, label: "Stereo", hint: "Two separate channels; common music default (no 5.1 in MP3)." },
  { code: 0x1, label: "Joint stereo", hint: "Shares stereo info to save bits; popular for VBR/low bitrates." },
  { code: 0x2, label: "Dual channel", hint: "Two independent mono streams; bilingual/broadcast use." },
  { code: 0x3, label: "Single channel", hint: "Mono; halves bitrate needs, typical for voice content." }
];

export const MPEG_VERSION_LABEL_TO_CODE = new Map(
  MPEG_VERSION_OPTS.map(({ code, label }) => [label, code])
);
export const LAYER_LABEL_TO_CODE = new Map(LAYER_OPTS.map(({ code, label }) => [label, code]));
export const CHANNEL_MODE_LABEL_TO_CODE = new Map(
  CHANNEL_MODE_OPTS.map(({ code, label }) => [label, code])
);

export function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "Unknown";
  const rounded = Math.round(seconds);
  const minutes = Math.floor(rounded / 60);
  const secs = rounded % 60;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  if (hours > 0) {
    return `${hours}:${mins.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  }
  return `${minutes}:${secs.toString().padStart(2, "0")}`;
}

export function formatBoolean(value) {
  return value ? "Yes" : "No";
}

export function wrapValue(valueHtml, tooltip) {
  if (!tooltip) return valueHtml;
  return `<span class="valueHint" title="${escapeHtml(tooltip)}">${valueHtml}</span>`;
}

export function valueWithNote(valueHtml, note) {
  if (!note) return valueHtml;
  return `${valueHtml}<div class="smallNote">${escapeHtml(note)}</div>`;
}

export function valueWithHint(valueHtml, tooltip) {
  return tooltip ? wrapValue(valueHtml, tooltip) : valueHtml;
}

export function withFieldNote(valueHtml, fieldNote) {
  if (!fieldNote) return valueHtml;
  return valueWithNote(valueHtml, fieldNote);
}

export function renderEnumChips(selectedCode, options) {
  const chips = options
    .map(({ code, label, hint }) => {
      const cls = code === selectedCode ? "opt sel" : "opt dim";
      const title = hint ? ` title="${escapeHtml(hint)}"` : "";
      return `<span class="${cls}"${title}>${escapeHtml(label)}</span>`;
    })
    .join("");
  return `<div class="optionsRow">${chips}</div>`;
}

export function describeMpegVersion(version) {
  if (!version) {
    return "MPEG audio version parsed from the first frame; valid values are 1, 2, and 2.5 (no other profiles in MP3).";
  }
  if (version.includes("Version 1")) {
    return `${version} - common high-sample-rate profile (default for most music).`;
  }
  if (version.includes("Version 2.5")) {
    return `${version} - low-sample-rate extension, rare outside voice/streaming content.`;
  }
  if (version.includes("Version 2")) {
    return `${version} - half-rate profile (22/24/16 kHz) used for low bitrates; less common than Version 1.`;
  }
  return `${version} - unusual or reserved value from the header.`;
}

export function describeLayer(layer) {
  if (!layer) {
    return "MPEG layer chooses the codec flavor; MP3 is Layer III. Only Layers I/II/III exist here.";
  }
  if (layer === "Layer III") return "Layer III - the MP3 codec; dominant/default for consumer audio (not a quality grade).";
  if (layer === "Layer II") return "Layer II - MP2 broadcast-style audio; uncommon inside .mp3 files.";
  if (layer === "Layer I") return "Layer I - earliest MPEG audio layer; rare in the wild.";
  return `${layer} - reported by the MPEG header.`;
}

export function describeChannelMode(mode) {
  if (!mode) {
    return "Channel mode is a 2-bit field with four legal values: Stereo, Joint stereo, Dual channel, Single channel (mono). MP3 does not support 5.1 multichannel.";
  }
  switch (mode) {
    case "Stereo":
      return "Stereo - two separate channels; common default for music. MP3 has no 5.1 mode.";
    case "Joint stereo":
      return "Joint stereo - shares info between channels to save bits; popular for VBR/low bitrate encodes (still two-channel, not 5.1).";
    case "Dual channel":
      return "Dual channel - two independent mono streams; rare, used for bilingual/broadcast tracks (not surround).";
    case "Single channel":
      return "Single channel - mono; halves bitrate needs, typical for voice content.";
    default:
      return `${mode} - parsed from MPEG header (reserved values are possible).`;
  }
}

export function describeSampleRate(sampleRateHz) {
  if (!sampleRateHz) return "Sample rate decoded from the MPEG header.";
  if (sampleRateHz >= 44100) return `${sampleRateHz} Hz - standard CD-quality rate for MP3 audio.`;
  if (sampleRateHz >= 32000) return `${sampleRateHz} Hz - mid-tier sample rate for low-bitrate encodes.`;
  return `${sampleRateHz} Hz - low sample rate (often voice/streaming content).`;
}

export function describeBitrate(bitrateKbps, isVbr) {
  if (!bitrateKbps) return "Bitrate comes from the MPEG table (preset steps only).";
  const vbrText = isVbr ? "variable bitrate " : "";
  if (bitrateKbps >= 256) return `${bitrateKbps} kbps ${vbrText}- high bitrate (typical for music).`;
  if (bitrateKbps >= 128) return `${bitrateKbps} kbps ${vbrText}- common music bitrate.`;
  return `${bitrateKbps} kbps ${vbrText}- low bitrate (voice or aggressive compression).`;
}

export function describeDuration(seconds) {
  if (!Number.isFinite(seconds)) return "Estimated duration of the audio stream.";
  if (seconds < 10) return "Very short clip; could be a ringtone, intro, or truncated file.";
  if (seconds > 600) return "Long duration; likely a full album, mix, or lengthy recording.";
  return "Approximate duration derived from frames, bitrate, or VBR headers.";
}

export function describeAudioOffset(offset) {
  if (offset == null) return "Offset of the first MPEG frame after any tags or junk.";
  if (offset === 0) return "Audio starts immediately at the beginning of the file.";
  if (offset < 1024) return `${offset} B of metadata/padding before the first frame.`;
  return `${offset} B before audio starts; likely ID3 metadata or padding.`;
}

export function describeAudioBytes(audioBytes) {
  if (!audioBytes) return "Estimated size of MPEG audio payload.";
  return `${audioBytes} B of MPEG frame data (approximate).`;
}

export function describeVbrFlag(isVbr) {
  if (isVbr == null) return "Whether the MPEG frames indicate variable bitrate.";
  return isVbr
    ? "Variable bitrate detected (frames differ in size)."
    : "Constant bitrate detected (frames have uniform size).";
}

export function describeId3v2(hasId3v2) {
  if (hasId3v2 == null) return "Whether an ID3v2 tag is present at the start of the file.";
  return hasId3v2
    ? "ID3v2 tag found (modern metadata with cover art and rich fields)."
    : "No ID3v2 tag detected (file may still have other tags).";
}

export function describeId3v1(hasId3v1) {
  if (hasId3v1 == null) return "Whether a legacy ID3v1 footer is present at the end of the file.";
  return hasId3v1
    ? "ID3v1 footer found (128-byte legacy tag)."
    : "No ID3v1 footer detected.";
}

export function describeApe(hasApe) {
  if (hasApe == null) return "Whether an APEv2 metadata block exists (ReplayGain or extra tags).";
  return hasApe ? "APEv2 metadata present (often carries ReplayGain)." : "No APE metadata detected.";
}

export function describeLyrics3(hasLyrics) {
  if (hasLyrics == null) return "Whether a Lyrics3 block exists near the end of the file.";
  return hasLyrics ? "Lyrics3 metadata present (rare format)." : "No Lyrics3 metadata detected.";
}
