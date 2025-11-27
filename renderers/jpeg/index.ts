"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import { renderJpegExifSummary } from "./exif-summary.js";
import { renderJfifSummary } from "./jfif-summary.js";
import type { JpegComment, JpegParseResult, JpegSegment } from "../../analyzers/jpeg/types.js";

export function renderJpeg(jpeg: JpegParseResult | null): string {
  if (!jpeg) return "";
  const {
    size,
    sof,
    hasJfif,
    hasExif,
    hasIcc,
    hasAdobe,
    hasRar,
    hasEoi,
    segmentCount,
    segments,
    jfif,
    exif,
    comments
  } = jpeg;

  const out: string[] = [];

  out.push("<h3>JPEG structure</h3>");
  out.push("<dl>");

  out.push(
    renderDefinitionRow("File size", escapeHtml(formatHumanSize(size)))
  );

  if (sof && sof.width && sof.height) {
    out.push(
      renderDefinitionRow(
        "Dimensions",
        `${sof.width} x ${sof.height} px`
      )
    );
    out.push(
      renderDefinitionRow(
        "Color components",
        `${sof.components || "?"}`,
        "Number of color channels used by this JPEG (typically 3 for RGB or YCbCr)."
      )
    );
    out.push(
      renderDefinitionRow(
        "Sampling",
        escapeHtml(sof.markerName || ""),
        "Sampling indicates which JPEG encoding is used (baseline/progressive) and chroma subsampling."
      )
    );
  } else {
    out.push(renderDefinitionRow("Dimensions", "Unknown"));
  }

  out.push(
    renderDefinitionRow(
      "EXIF / metadata",
      hasExif ? "Present" : "Not detected",
      "EXIF stores camera settings (time, exposure, ISO, GPS, etc.)."
    )
  );

  if (jfif) {
    out.push(renderJfifSummary(jfif));
  } else {
    out.push(
      renderDefinitionRow(
        "JFIF header",
        hasJfif ? "Present" : "Not detected",
        "JFIF (JPEG File Interchange Format) is the original JPEG container header with basic metadata such as pixel density and aspect ratio."
      )
    );
  }

  out.push(
    renderDefinitionRow(
      "ICC profile",
      hasIcc ? "Present" : "Not detected",
      "ICC color profile describes how to interpret RGB values; without it viewers assume a default (usually sRGB)."
    )
  );

  out.push(
    renderDefinitionRow(
      "Adobe/Photoshop tags",
      hasAdobe ? "Present" : "Not detected",
      "Adobe-specific segments (APP13/APP14) may carry Photoshop resources or color information."
    )
  );

  out.push(
    renderDefinitionRow(
      "RAR overlay",
      hasRar ? "Embedded RAR archive detected" : "No RAR signature found",
      "Some polyglot files hide a RAR archive after the JPEG data; this checks for a RAR signature anywhere in the file."
    )
  );

  out.push(
    renderDefinitionRow(
      "End marker (EOI)",
      hasEoi ? "Found" : "Not found",
      "EOI is the logical end-of-image marker. If missing, the file may be truncated or may have extra data appended."
    )
  );

  out.push(
    renderDefinitionRow(
      "Segment count",
      String(segmentCount),
      "Number of JPEG header segments (APPn, DQT, DHT, SOFn, SOS, etc.). Typical photos have a few dozen segments; very large counts usually mean lots of metadata or extra data."
    )
  );

  if (comments && comments.length) {
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
  }

  out.push("</dl>");

  if (exif) {
    out.push(renderJpegExifSummary(exif));
  }

  if (segments && segments.length) {
    out.push("<h4>Segments</h4>");
    out.push(
      "<p>Each JPEG segment begins with a 0xFFxx marker. " +
        "Marker shows the two-byte code in hexadecimal, Name is the known marker type " +
        "(APPn, SOF, DQT, DHT, SOS, etc.; \"Segment\" means a generic or less common marker), " +
        "Offset is the byte position from the start of the file, and Length is the size in bytes.</p>"
    );
    out.push('<table class="byteView"><thead><tr>');
    out.push("<th>#</th><th>Marker</th><th>Name</th><th>Offset</th><th>Length (bytes)</th>");
    out.push("</tr></thead><tbody>");
    segments.forEach((seg: JpegSegment, idx) => {
      const markerHex = toHex32(seg.marker, 4);
      const offHex = toHex32(seg.offset, 8);
      const lenHex = toHex32(seg.length, 8);
      const prettyLen = `${seg.length} B`;
      const name = seg.name || "";
      let nameHint = "";
      switch (seg.marker) {
        case 0xffe1:
          nameHint =
            "APP1 segment, typically used for EXIF or XMP metadata. Multiple APP1 segments are common (e.g., separate EXIF and XMP blocks).";
          break;
        case 0xffe0:
          nameHint =
            "APP0 / JFIF header with basic JPEG metadata (pixel density, aspect ratio, optional thumbnail).";
          break;
        case 0xffdb:
          nameHint =
            "DQT (Define Quantization Tables) — controls how strongly different spatial frequencies are compressed. Several DQT segments are normal when different tables are used for luminance/chrominance or multiple components.";
          break;
        case 0xffc4:
          nameHint =
            "DHT (Define Huffman Tables) — entropy coding tables for JPEG data. Multiple DHT segments are expected for DC/AC and for different color components.";
          break;
        case 0xffc0:
          nameHint =
            "SOF0 (Start Of Frame, baseline DCT) — contains image dimensions, precision and component sampling. Typically appears once per image.";
          break;
        case 0xffc1:
        case 0xffc2:
          nameHint =
            "SOF1/SOF2 (Start Of Frame, extended/progressive) — alternative JPEG encodings that send image data in multiple passes.";
          break;
        case 0xffda:
          nameHint =
            "SOS (Start Of Scan) — beginning of compressed image data. Progressive JPEGs can have several SOS segments for different passes.";
          break;
        case 0xffdd:
          nameHint =
            "DRI (Define Restart Interval) — tells the decoder how often restart markers occur to improve error recovery.";
          break;
        case 0xfffe:
          nameHint =
            "COM (Comment) segment with free-form text, often added by encoders or tools. Multiple COM segments are allowed.";
          break;
        default:
          if (name === "Segment") {
            nameHint =
              "Generic or less common segment; marker not mapped to a specific name here.";
          }
          break;
      }
      out.push("<tr>");
      out.push(`<td>${idx}</td>`);
      out.push(`<td title="${markerHex}">${markerHex}</td>`);
      out.push(
        `<td${nameHint ? ` title="${escapeHtml(nameHint)}"` : ""}>${escapeHtml(
          name
        )}</td>`
      );
      out.push(`<td title="${offHex}">${seg.offset}</td>`);
      out.push(`<td title="${lenHex}">${prettyLen}</td>`);
      out.push("</tr>");
    });
    out.push("</tbody></table>");
  }

  return out.join("");
}
