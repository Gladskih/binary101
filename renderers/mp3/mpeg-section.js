"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";
import { formatBoolean, valueWithHint, withFieldNote } from "./formatting.js";

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

export function renderMpeg(mpeg) {
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
        valueWithHint(f.frameLengthBytes ? `${f.frameLengthBytes} B` : "Unknown", describeFrameLength(f.frameLengthBytes)),
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
          valueWithHint(escapeHtml(f.modeExtension), describeModeExtension(f.modeExtension, f.channelMode)),
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
