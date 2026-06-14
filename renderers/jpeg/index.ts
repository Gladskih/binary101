"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import { renderJpegExifSummary } from "./exif-summary.js";
import { renderJfifSummary } from "./jfif-summary.js";
import type { JpegComment, JpegParseResult, JpegSegment } from "../../analyzers/jpeg/types.js";

const renderJpegSofRows = (jpeg: JpegParseResult, out: string[]): void => {
  if (!jpeg.sof || !jpeg.sof.width || !jpeg.sof.height) {
    out.push(renderDefinitionRow("Dimensions", "Unknown"));
    return;
  }
  out.push(renderDefinitionRow("Dimensions", `${jpeg.sof.width} x ${jpeg.sof.height} px`));
  out.push(
    renderDefinitionRow(
      "Color components",
      `${jpeg.sof.components || "?"}`,
      "Number of color channels used by this JPEG (typically 3 for RGB or YCbCr)."
    )
  );
  out.push(
    renderDefinitionRow(
      "Sampling",
      escapeHtml(jpeg.sof.markerName || ""),
      "Sampling indicates which JPEG encoding is used (baseline/progressive) and chroma subsampling."
    )
  );
};

const renderJpegContainerRows = (jpeg: JpegParseResult, out: string[]): void => {
  out.push(
    renderDefinitionRow(
      "EXIF / metadata",
      jpeg.hasExif ? "Present" : "Not detected",
      "EXIF stores camera settings (time, exposure, ISO, GPS, etc.)."
    )
  );
  if (jpeg.jfif) {
    out.push(renderJfifSummary(jpeg.jfif));
  } else {
    out.push(
      renderDefinitionRow(
        "JFIF header",
        jpeg.hasJfif ? "Present" : "Not detected",
        "JFIF (JPEG File Interchange Format) is the original JPEG container header with basic metadata such as pixel density and aspect ratio."
      )
    );
  }
  out.push(
    renderDefinitionRow(
      "ICC profile",
      jpeg.hasIcc ? "Present" : "Not detected",
      "ICC color profile describes how to interpret RGB values; without it viewers assume a default (usually sRGB)."
    )
  );
};

const renderJpegDetectionRows = (jpeg: JpegParseResult, out: string[]): void => {
  out.push(
    renderDefinitionRow(
      "Adobe/Photoshop tags",
      jpeg.hasAdobe ? "Present" : "Not detected",
      "Adobe-specific segments (APP13/APP14) may carry Photoshop resources or color information."
    )
  );
  out.push(
    renderDefinitionRow(
      "RAR overlay",
      jpeg.hasRar ? "Embedded RAR archive detected" : "No RAR signature found",
      "Some polyglot files hide a RAR archive after the JPEG data; this checks for a RAR signature anywhere in the file."
    )
  );
  out.push(
    renderDefinitionRow(
      "End marker (EOI)",
      jpeg.hasEoi ? "Found" : "Not found",
      "EOI is the logical end-of-image marker. If missing, the file may be truncated or may have extra data appended."
    )
  );
  out.push(
    renderDefinitionRow(
      "Segment count",
      String(jpeg.segmentCount),
      "Number of JPEG header segments (APPn, DQT, DHT, SOFn, SOS, etc.). Typical photos have a few dozen segments; very large counts usually mean lots of metadata or extra data."
    )
  );
};

const renderJpegCommentRows = (comments: JpegComment[] | null | undefined, out: string[]): void => {
  if (!comments?.length) return;
  comments.forEach((comment: JpegComment, index) => {
    const label = comments.length === 1 ? "COM comment" : `COM comment #${index + 1}`;
    const suffix = comment.truncated ? " (truncated preview)" : "";
    out.push(
      renderDefinitionRow(
        label,
        escapeHtml((comment.text || "") + suffix),
        "Comment segments contain free-form text added by encoders or tools. " +
          "Bytes are interpreted as 8-bit characters; non-ASCII text may appear garbled."
      )
    );
  });
};

const describeJpegSegment = (seg: JpegSegment): string => {
  switch (seg.marker) {
    case 0xffe1:
      return "APP1 segment, typically used for EXIF or XMP metadata. Multiple APP1 segments are common (e.g., separate EXIF and XMP blocks).";
    case 0xffe0:
      return "APP0 / JFIF header with basic JPEG metadata (pixel density, aspect ratio, optional thumbnail).";
    case 0xffdb:
      return "DQT (Define Quantization Tables) â€” controls how strongly different spatial frequencies are compressed. Several DQT segments are normal when different tables are used for luminance/chrominance or multiple components.";
    case 0xffc4:
      return "DHT (Define Huffman Tables) â€” entropy coding tables for JPEG data. Multiple DHT segments are expected for DC/AC and for different color components.";
    case 0xffc0:
      return "SOF0 (Start Of Frame, baseline DCT) â€” contains image dimensions, precision and component sampling. Typically appears once per image.";
    case 0xffc1:
    case 0xffc2:
      return "SOF1/SOF2 (Start Of Frame, extended/progressive) â€” alternative JPEG encodings that send image data in multiple passes.";
    case 0xffda:
      return "SOS (Start Of Scan) â€” beginning of compressed image data. Progressive JPEGs can have several SOS segments for different passes.";
    case 0xffdd:
      return "DRI (Define Restart Interval) â€” tells the decoder how often restart markers occur to improve error recovery.";
    case 0xfffe:
      return "COM (Comment) segment with free-form text, often added by encoders or tools. Multiple COM segments are allowed.";
    default:
      return seg.name === "Segment"
        ? "Generic or less common segment; marker not mapped to a specific name here."
        : "";
  }
};

const renderJpegSegmentRow = (seg: JpegSegment, idx: number): string => {
  const markerHex = toHex32(seg.marker, 4);
  const offHex = toHex32(seg.offset, 8);
  const lenHex = toHex32(seg.length, 8);
  const nameHint = describeJpegSegment(seg);
  return (
    "<tr>" +
    `<td>${idx}</td>` +
    `<td title="${markerHex}">${markerHex}</td>` +
    `<td${nameHint ? ` title="${escapeHtml(nameHint)}"` : ""}>${escapeHtml(seg.name || "")}</td>` +
    `<td title="${offHex}">${seg.offset}</td>` +
    `<td title="${lenHex}">${seg.length} B</td>` +
    "</tr>"
  );
};

const renderJpegSegments = (segments: JpegSegment[] | null | undefined): string => {
  if (!segments?.length) return "";
  return [
    "<h4>Segments</h4>",
    "<p>Each JPEG segment begins with a 0xFFxx marker. " +
      "Marker shows the two-byte code in hexadecimal, Name is the known marker type " +
      "(APPn, SOF, DQT, DHT, SOS, etc.; \"Segment\" means a generic or less common marker), " +
      "Offset is the byte position from the start of the file, and Length is the size in bytes.</p>",
    '<table class="byteView"><thead><tr>',
    "<th>#</th><th>Marker</th><th>Name</th><th>Offset</th><th>Length (bytes)</th>",
    "</tr></thead><tbody>",
    segments.map(renderJpegSegmentRow).join(""),
    "</tbody></table>"
  ].join("");
};

export function renderJpeg(jpeg: JpegParseResult | null): string {
  if (!jpeg) return "";
  const out: string[] = [];
  out.push("<h3>JPEG structure</h3>");
  out.push("<dl>");
  out.push(renderDefinitionRow("File size", escapeHtml(formatHumanSize(jpeg.size))));
  renderJpegSofRows(jpeg, out);
  renderJpegContainerRows(jpeg, out);
  renderJpegDetectionRows(jpeg, out);
  renderJpegCommentRows(jpeg.comments, out);
  out.push("</dl>");
  if (jpeg.exif) out.push(renderJpegExifSummary(jpeg.exif));
  out.push(renderJpegSegments(jpeg.segments));
  return out.join("");
}
