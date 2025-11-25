"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatBoolean, valueWithHint, withFieldNote } from "./formatting.js";
import type { ApeTag, Id3v1Tag, Id3v2Tag, Lyrics3Tag } from "../../analyzers/mp3/types.js";

function describeId3Version(versionMajor: number | null | undefined): string {
  if (versionMajor == null) return "ID3v2 major.minor version from the tag header.";
  if (versionMajor >= 4) return `ID3v2.${versionMajor} - modern version; 2.3/2.4 are most common.`;
  if (versionMajor === 3) return "ID3v2.3 - widely supported and common default in many tools.";
  if (versionMajor === 2) return "ID3v2.2 - legacy compact form; rare in modern files.";
  return `ID3v2.${versionMajor} - unusual version value.`;
}

function describeExtendedHeader(hasExtended: boolean | null | undefined): string {
  if (hasExtended) {
    return "Extended header present - may include CRC/restrictions; uncommon but valid.";
  }
  return "No extended header (typical).";
}

function describeFooter(hasFooter: boolean | null | undefined): string {
  if (hasFooter) return "Footer present - tag mirrored at the end; rare but allowed by ID3v2.4.";
  return "No footer (typical for ID3v2).";
}

function describeUnsynchronisation(flag: boolean | null | undefined): string {
  if (flag) {
    return "Unsynchronisation used to avoid false frame sync bytes; seen in older tags, now less common.";
  }
  return "Unsynchronisation off (modern default).";
}

function describeDeclaredSize(size: number | null | undefined): string {
  return `${size} B declared tag size - includes frames only; large sizes often mean embedded images.`;
}

function describeApeSize(size: number | null | undefined): string {
  if (size == null) return "APE tag size as declared in the footer/header.";
  if (size < 1000) return `${size} B APE tag - tiny (likely ReplayGain only).`;
  if (size < 500000) return `${size} B APE tag - moderate metadata block.`;
  return `${size} B APE tag - large block (possible embedded data).`;
}

function describeLyricsSize(sizeEstimate: number | string | null | undefined): string {
  if (typeof sizeEstimate !== "number") return "Lyrics3 block size estimate.";
  if (sizeEstimate < 500) return `${sizeEstimate} B Lyrics3 block - tiny snippet.`;
  if (sizeEstimate < 5000) return `${sizeEstimate} B Lyrics3 block - short lyrics (rare format).`;
  return `${sizeEstimate} B Lyrics3 block - large lyrics section; unusual.`;
}

export function renderId3v2Frames(frames: Id3v2Tag["frames"] | null | undefined): string {
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
        const desc = detail.description ? `${escapeHtml(detail.description)} – ` : "";
        const url = escapeHtml(detail.url || "");
        return `<tr><td>${id}</td><td>${desc}${url}</td><td>${size}</td></tr>`;
      }
      if (detail.type === "apic") {
        const desc = detail.description ? ` (${escapeHtml(detail.description)})` : "";
        const info = `${escapeHtml(detail.pictureType)}${desc}, ${detail.imageSize} bytes, ${escapeHtml(detail.mimeType)}`;
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

export function renderId3v2(id3: Id3v2Tag | null | undefined): string {
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
        valueWithHint(
          formatBoolean(id3.flags.unsynchronisation),
          describeUnsynchronisation(id3.flags.unsynchronisation)
        ),
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

export function renderId3v1(id3v1: Id3v1Tag | null | undefined): string {
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

export function renderApe(ape: ApeTag | null | undefined): string {
  if (!ape) return "";
  const rows = [];
  rows.push(
    renderDefinitionRow(
      "Version",
      withFieldNote(
        valueWithHint(escapeHtml(ape.version || "Unknown"), "APEv2 version parsed from tag footer/header."),
        "APEv2 version (1.0 or 2.0)."
      )
    )
  );
  rows.push(
    renderDefinitionRow(
      "Size",
      withFieldNote(valueWithHint(`${ape.size || "Unknown"} B`, describeApeSize(ape.size)), "Declared APE tag size.")
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

export function renderLyrics(lyrics: Lyrics3Tag | null | undefined): string {
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
