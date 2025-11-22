"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";

const MPEG_VERSION_OPTS = [
  { code: 0x3, label: "MPEG Version 1", hint: "High sample-rate profile (44.1/48 kHz); common default." },
  { code: 0x2, label: "MPEG Version 2", hint: "Half-rate profile (22/24/16 kHz); lower-bitrate mode." },
  { code: 0x0, label: "MPEG Version 2.5", hint: "Low-rate extension (11/12/8 kHz); rare outside voice/streaming." }
];

const LAYER_OPTS = [
  { code: 0x3, label: "Layer I", hint: "Earliest MPEG audio layer; rare in MP3 files." },
  { code: 0x2, label: "Layer II", hint: "MP2 broadcast-style audio; uncommon inside .mp3 files." },
  { code: 0x1, label: "Layer III", hint: "MP3 codec; dominant/default for consumer audio." }
];

const CHANNEL_MODE_OPTS = [
  { code: 0x0, label: "Stereo", hint: "Two separate channels; common music default (no 5.1 in MP3)." },
  { code: 0x1, label: "Joint stereo", hint: "Shares stereo info to save bits; popular for VBR/low bitrates." },
  { code: 0x2, label: "Dual channel", hint: "Two independent mono streams; bilingual/broadcast use." },
  { code: 0x3, label: "Single channel", hint: "Mono; halves bitrate needs, typical for voice content." }
];

const MPEG_VERSION_LABEL_TO_CODE = new Map(
  MPEG_VERSION_OPTS.map(({ code, label }) => [label, code])
);

const LAYER_LABEL_TO_CODE = new Map(LAYER_OPTS.map(({ code, label }) => [label, code]));
const CHANNEL_MODE_LABEL_TO_CODE = new Map(
  CHANNEL_MODE_OPTS.map(({ code, label }) => [label, code])
);

function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "Unknown";
  const rounded = Math.round(seconds);
  const minutes = Math.floor(rounded / 60);
  const secs = rounded % 60;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  if (hours > 0) {
    return `${hours}:${mins.toString().padStart(2, "0")}:${secs
      .toString()
      .padStart(2, "0")}`;
  }
  return `${minutes}:${secs.toString().padStart(2, "0")}`;
}

function formatBoolean(value) {
  return value ? "Yes" : "No";
}

function wrapValue(valueHtml, tooltip) {
  if (!tooltip) return valueHtml;
  return `<span class="valueHint" title="${escapeHtml(tooltip)}">${valueHtml}</span>`;
}

function valueWithNote(valueHtml, note) {
  if (!note) return valueHtml;
  return `${valueHtml}<div class="smallNote">${escapeHtml(note)}</div>`;
}

function valueWithHint(valueHtml, tooltip) {
  return tooltip ? wrapValue(valueHtml, tooltip) : valueHtml;
}

function withFieldNote(valueHtml, fieldNote) {
  if (!fieldNote) return valueHtml;
  return valueWithNote(valueHtml, fieldNote);
}

function renderEnumChips(selectedCode, options) {
  const chips = options
    .map(({ code, label, hint }) => {
      const cls = code === selectedCode ? "opt sel" : "opt dim";
      const title = hint ? ` title="${escapeHtml(hint)}"` : "";
      return `<span class="${cls}"${title}>${escapeHtml(label)}</span>`;
    })
    .join("");
  return `<div class="optionsRow">${chips}</div>`;
}

function describeMpegVersion(version) {
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

function describeLayer(layer) {
  if (!layer) {
    return "MPEG layer chooses the codec flavor; MP3 is Layer III. Only Layers I/II/III exist here.";
  }
  if (layer === "Layer III") return "Layer III - the MP3 codec; dominant/default for consumer audio (not a quality grade).";
  if (layer === "Layer II") return "Layer II - MP2 broadcast-style audio; uncommon inside .mp3 files.";
  if (layer === "Layer I") return "Layer I - earliest MPEG audio layer; rare in the wild.";
  return `${layer} - reported by the MPEG header.`;
}

function describeChannelMode(mode) {
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
      return `${mode} - channel allocation from the frame header; only Stereo, Joint stereo, Dual channel, or Single channel are valid in MP3.`;
  }
}

function describeSampleRate(sampleRateHz) {
  if (!sampleRateHz) {
    return "Sample rate (Hz) from the MPEG header; MP3 limits this to a small table depending on version (44.1/48/32 kHz for v1; lower for v2/2.5).";
  }
  if (sampleRateHz === 44100) return "44100 Hz - CD-quality rate; the most popular choice for MP3 music.";
  if (sampleRateHz === 48000) return "48000 Hz - video/broadcast rate; common but slightly less typical for MP3 music.";
  if (sampleRateHz === 32000) return "32000 Hz - lower rate for speech/older hardware; uncommon for music.";
  if (sampleRateHz === 24000 || sampleRateHz === 22050) {
    return `${sampleRateHz} Hz - half-rate profile used for low bitrates; rare for music releases.`;
  }
  if (sampleRateHz <= 16000) {
    return `${sampleRateHz} Hz - very low sample rate (voice or constrained bandwidth), rare for MP3 music.`;
  }
  return `${sampleRateHz} Hz sample rate from the header.`;
}

function describeBitrate(bitrateKbps, isVbr) {
  const basis = isVbr ? "average for variable bitrate" : "constant/target bitrate";
  if (!bitrateKbps) {
    return `Bitrate controls size versus quality; value is the ${basis} derived from the first frame or VBR header. MP3 uses discrete table values, not arbitrary kbps.`;
  }
  if (bitrateKbps >= 256) return `${bitrateKbps} kbps (${basis}) - very high quality, less common for compact files.`;
  if (bitrateKbps >= 192) return `${bitrateKbps} kbps (${basis}) - high quality, popular modern setting.`;
  if (bitrateKbps >= 128) return `${bitrateKbps} kbps (${basis}) - classic MP3 default; widely compatible.`;
  if (bitrateKbps >= 96) return `${bitrateKbps} kbps (${basis}) - mid/streaming quality; artifacts likely on music.`;
  return `${bitrateKbps} kbps (${basis}) - very low, typically for voice or bandwidth-constrained use (rare for music).`;
}

function describeDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "Duration is estimated from bitrate, frame counts, or VBR header; unknown when the file is tiny or malformed.";
  }
  if (seconds < 30) {
    return `${formatDuration(seconds)} runtime - very short clip or truncated sample.`;
  }
  if (seconds <= 600) {
    return `${formatDuration(seconds)} runtime - typical track length.`;
  }
  return `${formatDuration(seconds)} runtime - long recording (podcast, audiobook, or live set).`;
}

function describeAudioOffset(offset) {
  if (offset == null) {
    return "Byte offset of the first MPEG frame; ID3v2 tags or junk data push audio farther into the file.";
  }
  if (offset === 0) return "Audio starts at byte 0; no leading ID3v2 or padding.";
  if (offset < 10000) return `${offset} bytes before audio - small front tag or encoder delay (common).`;
  if (offset < 200000) {
    return `${offset} bytes before audio - likely ID3v2 tag with cover art; still common in real files.`;
  }
  return `${offset} bytes before audio - unusually large lead-in, could be oversized metadata or embedded data.`;
}

function describeAudioBytes(audioBytes) {
  if (!audioBytes) {
    return "Estimated MPEG audio payload length, excluding leading/trailing tags.";
  }
  if (audioBytes < 50000) return `${formatHumanSize(audioBytes)} of audio data - tiny preview or test tone.`;
  if (audioBytes < 5_000_000) return `${formatHumanSize(audioBytes)} of audio data - short clip or demo length.`;
  return `${formatHumanSize(audioBytes)} of audio data - typical full track or longer recording.`;
}

function describeVbrFlag(isVbr) {
  if (isVbr) {
    return "Variable bitrate (VBR) adjusts frame bitrate to keep quality consistent; common for modern encodes.";
  }
  return "Constant bitrate (CBR) keeps every frame the same bitrate; predictable size and older default.";
}

function describeId3v2(hasId3v2) {
  if (hasId3v2) {
    return "ID3v2 tag at the start of the file; stores modern metadata and cover art (most MP3s have this).";
  }
  return "No ID3v2 tag detected; file may be stripped metadata or very old.";
}

function describeId3v1(hasId3v1) {
  if (hasId3v1) {
    return "ID3v1 is a 128-byte trailer with plain text fields; legacy and often redundant when ID3v2 is present.";
  }
  return "No ID3v1 trailer found; modern files often omit it.";
}

function describeApe(hasApe) {
  if (hasApe) {
    return "APE tag detected (used for ReplayGain and rich metadata); uncommon in MP3 but supported by some tools.";
  }
  return "No APE tag detected; typical unless ReplayGain/extended metadata was added by certain tools.";
}

function describeLyrics3(hasLyrics) {
  if (hasLyrics) {
    return "Lyrics3 tag stores plain-text lyrics near the end of the file; rare and mostly found in older collections.";
  }
  return "No Lyrics3 tag detected; absence is the normal/default case.";
}

function describeFrameOffset(offset) {
  return offset === 0
    ? "First MPEG frame starts at the beginning of the file."
    : `${offset} B offset - audio begins after tags or padding.`;
}

function describeFrameLength(length) {
  if (!length) {
    return "Frame length could not be computed from the header fields.";
  }
  if (length < 200) return `${length} B per frame - extremely small, typical of very low bitrate audio.`;
  if (length < 500) return `${length} B per frame - small frame size; low bitrate or short samples.`;
  if (length < 1500) return `${length} B per frame - typical MP3 frame size for music.`;
  return `${length} B per frame - unusually large; check for parsing issues or very high bitrates.`;
}

function describeSamplesPerFrame(samples) {
  if (!samples) return "Number of PCM samples carried by one MPEG frame.";
  if (samples === 1152) return "1152 samples per frame - standard for MPEG1 Layer III (common).";
  if (samples === 576) return "576 samples per frame - short blocks for MPEG2/2.5 Layer III (low bitrate mode).";
  if (samples === 384) return "384 samples per frame - typical of Layer I (rare in MP3 files).";
  return `${samples} samples per frame from header.`;
}

function describeCrc(hasCrc) {
  if (hasCrc) {
    return "CRC16 present: decoder can verify frame integrity; rarely used because it costs extra bits.";
  }
  return "No CRC (most encoders default to this to save bits).";
}

function describePadding(padding) {
  if (padding) {
    return "Padding bit set - occasional extra slot to keep constant bitrate timing; normal for some bitrates.";
  }
  return "No padding on this frame - also normal; encoders toggle this to maintain timing.";
}

function describePrivateBit(privateBit) {
  if (privateBit) {
    return "Private bit is set; reserved for encoder-specific flags (rarely used by players).";
  }
  return "Private bit clear - common default; field is free for encoder use.";
}

function describeCopyright(copyright) {
  if (copyright) {
    return "Copyright bit set - indicates protected content; seldom relied on by players.";
  }
  return "Copyright bit clear - common default for user-encoded files.";
}

function describeOriginal(original) {
  if (original) {
    return "Original bit set - marked as an original stream (common for encoder output).";
  }
  return "Original bit clear - marked as a copy; uncommon.";
}

function describeModeExtension(modeExtension, channelMode) {
  if (!modeExtension) {
    return "Mode extension applies only to Joint stereo; intensity/MS stereo choices help save bitrate.";
  }
  return `${modeExtension} - stereo coding tool used when channel mode is ${channelMode}; MS stereo is the popular option.`;
}

function describeEmphasis(emphasis) {
  if (!emphasis) return "Emphasis flag requests de-emphasis EQ on playback; rarely used today.";
  if (emphasis === "None") return "No emphasis (default/typical).";
  return `${emphasis} emphasis - legacy feature, rare to see in modern files.`;
}

function describeSecondFrame(validated) {
  if (validated === true) {
    return "Second frame header matches the first one; suggests a consistent stream.";
  }
  if (validated === false) {
    return "Expected a second frame but it did not match; file may be truncated or header may be a false sync.";
  }
  return "Second frame could not be checked.";
}

function describeNonAudioBytes(nonAudioBytes) {
  if (nonAudioBytes == null) return "Bytes outside MPEG frames (front tags + trailing tags/junk).";
  if (nonAudioBytes === 0) return "No non-audio padding detected after the first frame.";
  if (nonAudioBytes < 1000) return `${formatHumanSize(nonAudioBytes)} of non-audio data - small tags or padding.`;
  if (nonAudioBytes < 2_000_000) {
    return `${formatHumanSize(nonAudioBytes)} of non-audio data - likely tags or embedded cover art (common).`;
  }
  return `${formatHumanSize(nonAudioBytes)} of non-audio data - unusually large; may contain bundled files or junk.`;
}

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

function describeId3Version(versionMajor) {
  if (versionMajor == null) return "ID3v2 major.minor version from the tag header.";
  if (versionMajor >= 4) return `ID3v2.${versionMajor} - modern version; 2.3/2.4 are most common.`;
  if (versionMajor === 3) return "ID3v2.3 - widely supported and common default in many tools.";
  if (versionMajor === 2) return "ID3v2.2 - legacy compact form; rare in modern files.";
  return `ID3v2.${versionMajor} - unusual version value.`;
}

function describeExtendedHeader(hasExtended) {
  if (hasExtended) {
    return "Extended header present - may include CRC/restrictions; uncommon but valid.";
  }
  return "No extended header (typical).";
}

function describeFooter(hasFooter) {
  if (hasFooter) return "Footer present - tag mirrored at the end; rare but allowed by ID3v2.4.";
  return "No footer (typical for ID3v2).";
}

function describeUnsynchronisation(flag) {
  if (flag) {
    return "Unsynchronisation used to avoid false frame sync bytes; seen in older tags, now less common.";
  }
  return "Unsynchronisation off (modern default).";
}

function describeDeclaredSize(size) {
  return `${size} B declared tag size - includes frames only; large sizes often mean embedded images.`;
}

function describeApeSize(size) {
  if (size == null) return "APE tag size as declared in the footer/header.";
  if (size < 1000) return `${size} B APE tag - tiny (likely ReplayGain only).`;
  if (size < 500000) return `${size} B APE tag - moderate metadata block.`;
  return `${size} B APE tag - large block (possible embedded data).`;
}

function describeLyricsSize(sizeEstimate) {
  if (sizeEstimate == null) return "Lyrics3 block size estimate.";
  if (sizeEstimate < 500) return `${sizeEstimate} B Lyrics3 block - tiny snippet.`;
  if (sizeEstimate < 5000) return `${sizeEstimate} B Lyrics3 block - short lyrics (rare format).`;
  return `${sizeEstimate} B Lyrics3 block - large lyrics section; unusual.`;
}

function renderWarnings(issues) {
  if (!issues || issues.length === 0) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
}

function renderSummary(mp3) {
  const { summary, audioDataBytes } = mp3;
  if (!summary) return "";
  const rows = [];
  const versionCode = MPEG_VERSION_LABEL_TO_CODE.get(summary.mpegVersion);
  const layerCode = LAYER_LABEL_TO_CODE.get(summary.layer);
  const channelCode = CHANNEL_MODE_LABEL_TO_CODE.get(summary.channelMode);
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
        valueWithHint(
          audioDataBytes ? formatHumanSize(audioDataBytes) : "Unknown",
          describeAudioBytes(audioDataBytes)
        ),
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

function renderMpeg(mpeg) {
  if (!mpeg || !mpeg.firstFrame) return "";
  const f = mpeg.firstFrame;
  const rows = [];
  rows.push(
    renderDefinitionRow(
      "Frame offset",
      withFieldNote(
        valueWithHint(`${f.offset} B`, describeFrameOffset(f.offset)),
        "Position of the first MPEG frame relative to file start."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Frame length",
      withFieldNote(
        valueWithHint(
          f.frameLengthBytes ? `${f.frameLengthBytes} B` : "Unknown",
          describeFrameLength(f.frameLengthBytes)
        ),
        "Size of the first MPEG frame in bytes."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Samples per frame",
      withFieldNote(
        valueWithHint(f.samplesPerFrame || "Unknown", describeSamplesPerFrame(f.samplesPerFrame)),
        "PCM samples carried by one frame."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "CRC present",
      withFieldNote(
        valueWithHint(formatBoolean(f.hasCrc), describeCrc(f.hasCrc)),
        "CRC16 checksum bit for this frame."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Padding",
      withFieldNote(
        valueWithHint(formatBoolean(f.padding), describePadding(f.padding)),
        "Padding bit toggles extra slot to keep constant bitrate timing."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Private bit",
      withFieldNote(
        valueWithHint(formatBoolean(f.privateBit), describePrivateBit(f.privateBit)),
        "Reserved encoder-specific flag."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Copyright",
      withFieldNote(
        valueWithHint(formatBoolean(f.copyright), describeCopyright(f.copyright)),
        "Copyright flag from header."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Original",
      withFieldNote(
        valueWithHint(formatBoolean(f.original), describeOriginal(f.original)),
        "Marks stream as original vs copy."
      )
    )
  );
  if (f.modeExtension) {
    rows.push(
      renderDefinitionRow(
        "Mode extension",
        withFieldNote(
          valueWithHint(
            escapeHtml(f.modeExtension),
            describeModeExtension(f.modeExtension, f.channelMode)
          ),
          "Stereo coding tools used only when channel mode is Joint stereo."
        )
      )
    );
  }
  if (f.emphasis && f.emphasis !== "None") {
    rows.push(
      renderDefinitionRow(
        "Emphasis",
        withFieldNote(
          valueWithHint(escapeHtml(f.emphasis), describeEmphasis(f.emphasis)),
          "Playback de-emphasis request (legacy)."
        )
      )
    );
  }
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

function renderVbr(vbr) {
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

function renderId3v2Frames(frames) {
  if (!frames || frames.length === 0) return "<p>No frames parsed.</p>";
  const rows = frames
    .map(frame => {
      const id = escapeHtml(frame.id || "?");
      const size = frame.size != null ? `${frame.size} B` : "";
      const detail = frame.detail || {};
      if (detail.type === "text") {
        const parts = [];
        if (detail.description) parts.push(`<strong>${escapeHtml(detail.description)}:</strong>`);
        parts.push(escapeHtml(detail.value || "(empty)"));
        return `<tr><td>${id}</td><td>${parts.join(" ")}</td><td>${size}</td></tr>`;
      }
      if (detail.type === "url") {
        const desc = detail.description
          ? `${escapeHtml(detail.description)} → `
          : "";
        const url = escapeHtml(detail.url || "");
        return `<tr><td>${id}</td><td>${desc}${url}</td><td>${size}</td></tr>`;
      }
      if (detail.type === "apic") {
        const desc = detail.description
          ? ` (${escapeHtml(detail.description)})`
          : "";
        const info = `${escapeHtml(detail.pictureType)}${desc}, ${detail.imageSize} bytes, ${
          escapeHtml(detail.mimeType)
        }`;
        return `<tr><td>${id}</td><td>${info}</td><td>${size}</td></tr>`;
      }
      if (frame.id === "GEOB") {
        const preview = escapeHtml(detail.preview || "(binary)");
        const info = "GEOB (General Encapsulated Object) - arbitrary binary payload; preview shows hex.";
        return `<tr><td>${id}</td><td>${info} ${preview}</td><td>${size}</td></tr>`;
      }
      const preview = escapeHtml(detail.preview || "(binary)");
      return `<tr><td>${id}</td><td>${preview}</td><td>${size}</td></tr>`;
    })
    .join("");
  const tableHead =
    '<table class="byteView"><thead><tr><th>Frame</th><th>Value</th>' +
    '<th>Size</th></tr></thead><tbody>';
  return tableHead + rows + "</tbody></table>";
}

function renderId3v2(id3) {
  if (!id3) return "";
  const details = [];
  const version = `${id3.versionMajor}.${id3.versionRevision}`;
  details.push(
    renderDefinitionRow(
      "Version",
      withFieldNote(
        valueWithHint(escapeHtml(version), describeId3Version(id3.versionMajor)),
        "ID3v2 major.minor version."
      )
    )
  );
  details.push(
    renderDefinitionRow(
      "Extended header",
      withFieldNote(
        valueWithHint(formatBoolean(id3.flags.extendedHeader), describeExtendedHeader(id3.flags.extendedHeader)),
        "Whether optional extended header is present."
      )
    )
  );
  details.push(
    renderDefinitionRow(
      "Footer present",
      withFieldNote(
        valueWithHint(formatBoolean(id3.hasFooter), describeFooter(id3.hasFooter)),
        "ID3v2 footer mirrors the header at the end (rare)."
      )
    )
  );
  details.push(
    renderDefinitionRow(
      "Unsynchronisation",
      withFieldNote(
        valueWithHint(formatBoolean(id3.flags.unsynchronisation), describeUnsynchronisation(id3.flags.unsynchronisation)),
        "Unsynchronisation flag from tag header."
      )
    )
  );
  if (id3.extendedHeaderSize) {
    details.push(
      renderDefinitionRow(
        "Extended header size",
        withFieldNote(
          valueWithHint(
            `${id3.extendedHeaderSize} B`,
            "Bytes used by the optional ID3v2 extended header; appears only when that flag is set."
          ),
          "Size of the extended header when present."
        )
      )
    );
  }
  details.push(
    renderDefinitionRow(
      "Declared tag size",
      withFieldNote(
        valueWithHint(`${id3.size} B`, describeDeclaredSize(id3.size)),
        "Tag size declared in the ID3 header (frames only)."
      )
    )
  );
  const framesTable = renderId3v2Frames(id3.frames);
  return "<h4>ID3v2 metadata</h4><dl>" + details.join("") + "</dl>" + framesTable;
}

function renderId3v1(id3v1) {
  if (!id3v1) return "";
  const rows = [];
  rows.push(renderDefinitionRow("Title", escapeHtml(id3v1.title || "(empty)")));
  rows.push(renderDefinitionRow("Artist", escapeHtml(id3v1.artist || "(empty)")));
  rows.push(renderDefinitionRow("Album", escapeHtml(id3v1.album || "(empty)")));
  rows.push(renderDefinitionRow("Year", escapeHtml(id3v1.year || "(empty)")));
  rows.push(renderDefinitionRow("Comment", escapeHtml(id3v1.comment || "(empty)")));
  if (id3v1.trackNumber != null) {
    rows.push(renderDefinitionRow("Track", String(id3v1.trackNumber)));
  }
  const genreText = id3v1.genreName || `(code ${id3v1.genreCode})`;
  rows.push(renderDefinitionRow("Genre", escapeHtml(genreText)));
  return "<h4>ID3v1 tag</h4><dl>" + rows.join("") + "</dl>";
}

function renderApe(ape) {
  if (!ape) return "";
  const rows = [];
  rows.push(
    renderDefinitionRow(
      "Version",
      withFieldNote(
        valueWithHint(`0x${ape.version.toString(16)}`, "APE tag format version in hexadecimal."),
        "APE tag format version (hex)."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Size",
      withFieldNote(
        valueWithHint(`${ape.size || "Unknown"} B`, describeApeSize(ape.size)),
        "Declared APE tag size."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Items",
      withFieldNote(
        valueWithHint(
          ape.itemCount != null ? String(ape.itemCount) : "Unknown",
          "Number of key/value fields (ReplayGain, metadata, etc.)."
        ),
        "Count of APE metadata items."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Offset",
      withFieldNote(
        valueWithHint(`${ape.offset} B`, "Byte offset where the APE footer/header starts."),
        "File offset where the APE footer/header begins."
      )
    )
  );
  return "<h4>APE tag</h4><dl>" + rows.join("") + "</dl>";
}

function renderLyrics(lyrics) {
  if (!lyrics) return "";
  const rows = [];
  rows.push(renderDefinitionRow("Version", escapeHtml(lyrics.version)));
  if (lyrics.sizeEstimate != null) {
    rows.push(
      renderDefinitionRow(
        "Size",
        withFieldNote(
          valueWithHint(`${lyrics.sizeEstimate} B`, describeLyricsSize(lyrics.sizeEstimate)),
          "Estimated size of Lyrics3 block."
        )
      )
    );
  }
  if (lyrics.offset != null) {
    rows.push(
      renderDefinitionRow(
        "Offset",
        withFieldNote(
          valueWithHint(`${lyrics.offset} B`, "Byte offset where the Lyrics3 block begins."),
          "Byte offset of the Lyrics3 block."
        )
      )
    );
  }
  return "<h4>Lyrics3</h4><dl>" + rows.join("") + "</dl>";
}

export function renderMp3(mp3) {
  if (!mp3) return "";
  const out = [];
  out.push("<h3>MPEG audio (MP3)</h3>");
  if (!mp3.isMp3) {
    out.push(`<p>Not detected as MP3: ${escapeHtml(mp3.reason || "Unknown reason")}</p>`);
    out.push(renderWarnings(mp3.warnings));
    return out.join("");
  }
  out.push(renderSummary(mp3));
  out.push(renderMpeg(mp3.mpeg));
  out.push(renderVbr(mp3.vbr));
  out.push(renderId3v2(mp3.id3v2));
  out.push(renderId3v1(mp3.id3v1));
  out.push(renderApe(mp3.apeTag));
  out.push(renderLyrics(mp3.lyrics3));
  out.push(renderWarnings(mp3.warnings));
  return out.join("");
}
