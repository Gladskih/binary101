"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize } from "../../binary-utils.js";
import type {
  AsfCodecEntry,
  AsfContentDescription,
  AsfExtendedDescriptor,
  AsfParseResult,
  AsfStreamProperties
} from "../../analyzers/asf/types.js";

const fmt = (value: unknown): string =>
  value == null ? "Unknown" : typeof value === "number" ? String(value) : String(value);

const renderIssues = (issues: string[]): string => {
  if (!issues.length) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
};

const renderRows = (
  defs: Array<{ label: string; value: string; hint?: string }>
): string => defs.map(def => renderDefinitionRow(def.label, def.value, def.hint)).join("");

const renderContentDescription = (meta: AsfContentDescription | null): string => {
  if (!meta) return "";
  const defs = [
    { label: "Title", value: escapeHtml(meta.title || "None") },
    { label: "Author", value: escapeHtml(meta.author || "None") },
    { label: "Copyright", value: escapeHtml(meta.copyright || "None") },
    { label: "Description", value: escapeHtml(meta.description || "None") },
    { label: "Rating", value: escapeHtml(meta.rating || "None"), hint: "User or publisher rating tag." }
  ];
  if (meta.truncated) defs.push({ label: "Notice", value: "Metadata is truncated.", hint: "Field lengths exceeded the object size." });
  return `<h4>Content description</h4><dl>${renderRows(defs)}</dl>`;
};

const renderExtendedContent = (tags: AsfExtendedDescriptor[]): string => {
  if (!tags.length) return "";
  const rows = tags.map(tag => {
    const warn = tag.truncated ? ' class="dim"' : "";
    return `<tr${warn}><td>${escapeHtml(tag.name)}</td><td>${escapeHtml(tag.valueType)}</td><td>${escapeHtml(tag.value)}</td></tr>`;
  }).join("");
  return "<h4>Extended content descriptors</h4><p>Extended descriptors carry album, track, and custom tags.</p>" +
    '<table class="byteView"><thead><tr><th>Name</th><th>Type</th><th>Value</th></tr></thead>' +
    `<tbody>${rows}</tbody></table>`;
};

const renderCodecList = (codecs: AsfCodecEntry[]): string => {
  if (!codecs.length) return "";
  const rows = codecs.map(codec => {
    const warn = codec.truncated ? ' class="dim"' : "";
    return `<tr${warn}><td>${escapeHtml(codec.type)}</td><td>${escapeHtml(codec.name)}</td><td>${escapeHtml(codec.description)}</td><td>${codec.infoLength} B</td></tr>`;
  }).join("");
  return "<h4>Codec list</h4><p>Advertised codecs help players choose decoders for the streams.</p>" +
    '<table class="byteView"><thead><tr><th>Kind</th><th>Name</th><th>Description</th><th>Extra bytes</th></tr></thead>' +
    `<tbody>${rows}</tbody></table>`;
};

const renderObjectTable = (objects: AsfParseResult["objects"]): string => {
  if (!objects.length) return "";
  const rows = objects.map((obj, index) => {
    const warn = obj.truncated ? ' class="dim"' : "";
    return `<tr${warn}><td>${index}</td><td>${escapeHtml(obj.name)}</td><td>${escapeHtml(obj.guid || "")}</td><td>${obj.offset}</td><td>${obj.size ?? "?"} B</td></tr>`;
  }).join("");
  return "<h4>Objects</h4><p>ASF is organized into GUID-labelled objects. Sizes include the 24-byte object header.</p>" +
    '<table class="byteView"><thead><tr><th>#</th><th>Name</th><th>GUID</th><th>Offset</th><th>Size</th></tr></thead>' +
    `<tbody>${rows}</tbody></table>`;
};

const renderStreamFormat = (stream: AsfStreamProperties): string => {
  const typeSpecific = stream.typeSpecific;
  if (typeSpecific?.kind === "audio") {
    return renderRows([
      {
        label: "Audio format tag",
        value: escapeHtml(
          typeSpecific.formatName
            ? `${typeSpecific.formatName} (0x${(typeSpecific.formatTag ?? 0).toString(16)})`
            : `0x${(typeSpecific.formatTag ?? 0).toString(16)}`
        ),
        hint: "Identifies the audio codec; tags 0x0160-0x0164 cover Windows Media Audio."
      },
      { label: "Channels", value: fmt(typeSpecific.channels), hint: "Number of audio channels." },
      { label: "Sample rate", value: fmt(typeSpecific.sampleRate), hint: "Samples per second for the audio track." },
      { label: "Average bytes/sec", value: fmt(typeSpecific.avgBytesPerSec), hint: "Encoder target rate, used for buffering." },
      { label: "Bits per sample", value: fmt(typeSpecific.bitsPerSample), hint: "Audio sample depth per channel." },
      { label: "Block align", value: fmt(typeSpecific.blockAlign), hint: "Smallest addressable audio block (bytes)." }
    ]);
  }
  if (typeSpecific?.kind === "video") {
    return renderRows([
      { label: "Frame size", value: `${fmt(typeSpecific.width)} x ${fmt(typeSpecific.height)}`, hint: "Dimensions from the video info header." },
      { label: "Compression", value: escapeHtml(typeSpecific.compression || "Unknown"), hint: "FourCC from the bitmap header (e.g. WMV3)." },
      { label: "Frame rate", value: typeSpecific.frameRate ? `${typeSpecific.frameRate} fps` : "Unknown", hint: "Derived from AvgTimePerFrame in 100-ns units." },
      { label: "Bit depth", value: fmt(typeSpecific.bitCount), hint: "Bits per pixel reported by the bitmap header." },
      { label: "Bitrate", value: fmt(typeSpecific.bitRate), hint: "Target bits per second." }
    ]);
  }
  if (typeSpecific) return renderDefinitionRow("Opaque format data", escapeHtml(typeSpecific.note));
  return "";
};

const renderStreams = (streams: AsfStreamProperties[]): string => {
  if (!streams.length) return "<p>No stream properties found in the header.</p>";
  return streams.map((stream, index) => {
    const defs = [
      { label: "Stream type", value: escapeHtml(stream.streamTypeName), hint: "GUID identifying the payload type (audio, video, commands, etc.)." },
      { label: "Stream number", value: fmt(stream.streamNumber), hint: "Lower 7 bits of the flags field map packets to this stream." },
      { label: "Encrypted", value: stream.encrypted ? "Yes" : "No", hint: "Bit 15 of the flags marks encrypted payloads." },
      { label: "Time offset", value: fmt(stream.timeOffset), hint: "Offset in 100-ns units applied to timestamps in this stream." }
    ];
    return `<h4>Stream ${index + 1}</h4><dl>${renderRows(defs)}${renderStreamFormat(stream)}</dl>`;
  }).join("");
};

const renderFileProperties = (asf: AsfParseResult): string => {
  const fp = asf.fileProperties;
  if (!fp) return "";
  const defs = [
    { label: "File ID", value: escapeHtml(fp.fileId || "Unknown"), hint: "GUID uniquely identifying this ASF file." },
    { label: "Creation time", value: escapeHtml(fp.creationDate || "Unknown"), hint: "FILETIME (UTC) captured when the file was written." },
    { label: "Packets", value: fmt(fp.dataPackets), hint: "Packet count recorded in the header." },
    { label: "Play duration", value: fmt(fp.playDuration), hint: "100-ns units of presentation time." },
    { label: "Send duration", value: fmt(fp.sendDuration), hint: "Transport duration including retransmissions." },
    { label: "Preroll", value: fmt(fp.prerollMs), hint: "Milliseconds to skip before the first timestamp." },
    { label: "Packet size", value: `${fmt(fp.minPacketSize)} - ${fmt(fp.maxPacketSize)} bytes`, hint: "Expected minimum and maximum data packet sizes." },
    { label: "Flags", value: fp.flags != null ? `0x${fp.flags.toString(16)}` : "Unknown", hint: "Flag 0: broadcast; Flag 1: seekable." },
    { label: "Broadcast", value: fp.broadcast ? "Yes" : "No", hint: "Set for live broadcast captures." },
    { label: "Seekable", value: fp.seekable ? "Yes" : "No", hint: "Set when the file supports seeking." },
    { label: "Max bitrate", value: fmt(fp.maxBitrate), hint: "Maximum aggregate bit rate across all streams." }
  ];
  return "<h4>File properties</h4><dl>" + renderRows(defs) + "</dl>";
};

const renderSummary = (asf: AsfParseResult): string => {
  const defs = [
    {
      label: "Reported file size",
      value: asf.fileProperties?.fileSize != null ? escapeHtml(fmt(asf.fileProperties.fileSize)) : "Unknown",
      hint: "Value from the File Properties object (may differ from actual bytes on disk)."
    },
    { label: "Streams", value: escapeHtml(`${asf.streams.length} declared`), hint: "Count of Stream Properties objects in the header." },
    {
      label: "Duration",
      value: asf.fileProperties?.durationSeconds != null ? `${asf.fileProperties.durationSeconds} s` : "Unknown",
      hint: "Play duration in 100-ns units minus preroll."
    }
  ];
  if (asf.fileProperties?.maxBitrate != null) {
    defs.push({ label: "Max bitrate", value: `${asf.fileProperties.maxBitrate} bps`, hint: "Maximum bit rate allowed across all streams." });
  }
  if (asf.dataObject?.totalPackets != null) {
    defs.push({ label: "Data packets", value: fmt(asf.dataObject.totalPackets), hint: "Number of data packets recorded in the Data object." });
  }
  defs.push({
    label: "Unparsed tail",
    value: asf.stats.overlayBytes ? formatHumanSize(asf.stats.overlayBytes) : "None",
    hint: "Bytes left after the last parsed object."
  });
  return `<dl>${renderRows(defs)}</dl>`;
};

const renderHeaderExtension = (asf: AsfParseResult): string => {
  const ext = asf.headerExtension;
  if (!ext) return "";
  const defs = [
    { label: "Reserved GUID", value: escapeHtml(ext.reserved1 || "Unknown"), hint: "Should repeat the header extension GUID." },
    { label: "Reserved value", value: fmt(ext.reserved2), hint: "Expected to be 0x0006 in classic ASF files." },
    { label: "Extension data size", value: fmt(ext.dataSize), hint: "Length of the nested extension objects." },
    { label: "Nested objects", value: String(ext.objects.length), hint: "Objects carried inside the header extension." }
  ];
  return "<h4>Header extension</h4><dl>" + renderRows(defs) + "</dl>";
};

export const renderAsf = (parsed: AsfParseResult | null | unknown): string => {
  const asf = parsed as AsfParseResult | null;
  if (!asf) return "";
  const out: string[] = [];
  out.push("<h3>ASF / Windows Media</h3>");
  out.push(renderSummary(asf));
  out.push(renderFileProperties(asf));
  out.push("<h4>Streams</h4>");
  out.push(renderStreams(asf.streams));
  out.push(renderContentDescription(asf.contentDescription));
  out.push(renderExtendedContent(asf.extendedContent));
  out.push(renderCodecList(asf.codecList));
  out.push(renderHeaderExtension(asf));
  out.push(renderObjectTable(asf.objects));
  out.push(renderIssues(asf.issues));
  return out.join("");
};
