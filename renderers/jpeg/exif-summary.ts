"use strict";

import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { toHex32 } from "../../binary-utils.js";
import type { ExifData, ExifGps, ExifRational, ExifRawTag } from "../../analyzers/jpeg/types.js";

function formatRationalDisplay(r: ExifRational | null | undefined): number | null {
  if (!r || !r.num || !r.den) return null;
  if (r.den === 0) return null;
  return r.num / r.den;
}

function describeOrientation(value: number | null | undefined): string {
  if (value == null) return "Not specified";
  const map: Record<number, string> = {
    1: "1 (Top-left, normal)",
    2: "2 (Top-right, mirrored horizontally)",
    3: "3 (Bottom-right, rotated 180°)",
    4: "4 (Bottom-left, mirrored vertically)",
    5: "5 (Left-top, mirrored + 90° CW)",
    6: "6 (Right-top, rotated 90° CW)",
    7: "7 (Right-bottom, mirrored + 90° CCW)",
    8: "8 (Left-bottom, rotated 90° CCW)"
  };
  const label = map[value] || `${value} (non-standard)`;
  if (value === 1) {
    return `${label} — typical orientation`;
  }
  return `${label} — requires rotation when displaying`;
}

function describeExposureTime(r: ExifRational | null | undefined): string {
  const v = formatRationalDisplay(r);
  if (!v || v <= 0) return "Not available";
  if (v >= 1) {
    const text = `${v.toFixed(2)} s`;
    return `${text} — long exposure (blur likely without tripod)`;
  }
  const inv = 1 / v;
  const rounded = Math.round(inv);
  const frac = `1/${rounded}`;
  if (v < 1 / 4000) {
    return `${frac} s — extremely short exposure (very fast action)`;
  }
  if (v < 1 / 60) {
    return `${frac} s — fast shutter (freezing motion)`;
  }
  if (v < 1 / 2) {
    return `${frac} s — typical handheld range`;
  }
  return `${frac} s — slow shutter (motion blur or low light)`;
}

function describeFNumber(r: ExifRational | null | undefined): string {
  const v = formatRationalDisplay(r);
  if (!v || v <= 0) return "Not available";
  const rounded = Math.round(v * 10) / 10;
  if (rounded <= 1.8) return `f/${rounded} — very fast lens, very shallow depth of field`;
  if (rounded <= 2.8) return `f/${rounded} — fast lens, portraits / low light`;
  if (rounded <= 5.6) return `f/${rounded} — typical general-purpose aperture`;
  return `f/${rounded} — high f-number, more depth of field (less light)`;
}

function describeIso(iso: number | null | undefined): string {
  if (!iso || iso <= 0) return "Not specified";
  if (iso <= 64) return `ISO ${iso} — low noise, needs a lot of light`;
  if (iso <= 800) return `ISO ${iso} — typical everyday range`;
  if (iso <= 3200) return `ISO ${iso} — noticeable noise, low light photography`;
  return `ISO ${iso} — very high, strong noise likely`;
}

function describeFocalLength(r: ExifRational | null | undefined): string {
  const v = formatRationalDisplay(r);
  if (!v || v <= 0) return "Not available";
  const rounded = Math.round(v * 10) / 10;
  if (rounded < 24) return `${rounded} mm — ultra-wide / wide angle`;
  if (rounded < 50) return `${rounded} mm — wide/normal field of view`;
  if (rounded <= 85) return `${rounded} mm — short telephoto (portraits)`;
  if (rounded <= 200) return `${rounded} mm — telephoto (portrait / wildlife)`;
  return `${rounded} mm — super-telephoto, narrow field of view`;
}

function describeFlash(code: number | null | undefined): string {
  if (code == null) return "Not specified";
  const fired = (code & 0x1) !== 0;
  if (fired) {
    return `${code} — flash fired (subject likely brighter, possible reflections)`;
  }
  return `${code} — flash did not fire (ambient light only)`;
}

function describeExifDate(raw: string | null | undefined): string {
  if (!raw || typeof raw !== "string") return "Not specified";
  const trimmed = raw.trim();
  const parts = trimmed.split(" ");
  if (parts.length !== 2) {
    return `${trimmed} — camera local time (format not standard)`;
  }
  const [dateToken, timeToken] = parts;
  if (!dateToken || !timeToken) return `${trimmed} — camera local time (format not standard)`;
  const datePart = dateToken.replace(/:/g, "-");
  const isoCandidate = `${datePart}T${timeToken}`;
  const d = new Date(isoCandidate);
  if (Number.isNaN(d.getTime())) {
    return `${trimmed} — camera local time (cannot parse)`;
  }
  const now = new Date();
  const diffMs = d.getTime() - now.getTime();
  const maxFutureMs = 26 * 60 * 60 * 1000;
  if (diffMs > maxFutureMs) {
    return `${trimmed} — camera clock looks misconfigured (far in the future vs. now)`;
  }
  const year = d.getFullYear();
  if (year < 1990) {
    return `${trimmed} — camera clock looks misconfigured (very old year)`;
  }
  return `${trimmed} — camera local time (time zone not recorded in EXIF)`;
}

function rationalToDegreesTriple(triple: ExifRational[] | null | undefined): number | null {
  if (!triple || triple.length !== 3) return null;
  const d = formatRationalDisplay(triple[0]);
  const m = formatRationalDisplay(triple[1]);
  const s = formatRationalDisplay(triple[2]);
  if (d == null || m == null || s == null) return null;
  return d + m / 60 + s / 3600;
}

function describeGps(gps: ExifGps | null | undefined): string {
  if (!gps) return "Not available";
  const latDeg = rationalToDegreesTriple(gps.lat);
  const lonDeg = rationalToDegreesTriple(gps.lon);
  if (latDeg == null || lonDeg == null) return "Not available";
  const latSign = gps.latRef === "S" ? -1 : 1;
  const lonSign = gps.lonRef === "W" ? -1 : 1;
  const lat = latDeg * latSign;
  const lon = lonDeg * lonSign;
  const latText = `${Math.abs(lat).toFixed(6)}° ${lat >= 0 ? "N" : "S"}`;
  const lonText = `${Math.abs(lon).toFixed(6)}° ${lon >= 0 ? "E" : "W"}`;
  return `${latText}, ${lonText} — approximate capture location`;
}

export function renderJpegExifSummary(exif: ExifData | null): string {
  if (!exif) return "";
  const out: string[] = [];
  out.push("<h4>EXIF summary</h4>");
  out.push("<dl>");
  out.push(
    renderDefinitionRow(
      "Camera make",
      escapeHtml(exif.make || "Not specified")
    )
  );
  out.push(
    renderDefinitionRow(
      "Camera model",
      escapeHtml(exif.model || "Not specified")
    )
  );
  out.push(
    renderDefinitionRow(
      "Orientation",
      escapeHtml(describeOrientation(exif.orientation))
    )
  );
  out.push(
    renderDefinitionRow(
      "Capture time",
      escapeHtml(describeExifDate(exif.dateTimeOriginal))
    )
  );
  out.push(
    renderDefinitionRow(
      "ISO",
      escapeHtml(describeIso(exif.iso))
    )
  );
  out.push(
    renderDefinitionRow(
      "Exposure time",
      escapeHtml(describeExposureTime(exif.exposureTime))
    )
  );
  out.push(
    renderDefinitionRow(
      "Aperture (f-number)",
      escapeHtml(describeFNumber(exif.fNumber))
    )
  );
  out.push(
    renderDefinitionRow(
      "Focal length",
      escapeHtml(describeFocalLength(exif.focalLength))
    )
  );
  out.push(
    renderDefinitionRow(
      "Flash",
      escapeHtml(describeFlash(exif.flash))
    )
  );
  if (exif.pixelXDimension && exif.pixelYDimension) {
    out.push(
      renderDefinitionRow(
        "Recorded pixel dimensions",
        `${exif.pixelXDimension} x ${exif.pixelYDimension} px`
      )
    );
  }
  out.push(
    renderDefinitionRow(
      "GPS",
      escapeHtml(describeGps(exif.gps))
    )
  );
  out.push("</dl>");

  const raw: ExifRawTag[] = Array.isArray(exif.rawTags) ? exif.rawTags : [];
  if (raw.length) {
    const TAG_INFO = new Map([
      [0x010f, { name: "Make", desc: "Camera manufacturer name." }],
      [0x0110, { name: "Model", desc: "Camera model name." }],
      [0x011a, { name: "XResolution", desc: "Horizontal pixel density in EXIF units." }],
      [0x011b, { name: "YResolution", desc: "Vertical pixel density in EXIF units." }],
      [
        0x0128,
        {
          name: "ResolutionUnit",
          desc: "Units for X/Y resolution: 2 = inch, 3 = centimeter."
        }
      ],
      [0x0131, { name: "Software", desc: "Name and version of the software or firmware." }],
      [0x0132, { name: "DateTime", desc: "Last modification time of the file." }],
      [0x0213, { name: "YCbCrPositioning", desc: "Specifies the positioning of chroma components." }],
      [0x8769, { name: "ExifIFDPointer", desc: "Offset of the Exif IFD." }],
      [0x8825, { name: "GPSInfoIFDPointer", desc: "Offset of the GPS IFD." }],
      [0x829a, { name: "ExposureTime", desc: "Actual exposure time (shutter speed), in seconds." }],
      [0x829d, { name: "FNumber", desc: "Actual aperture value (f-number)." }],
      [0x8822, { name: "ExposureProgram", desc: "Program used by camera (manual, normal, aperture priority, etc.)." }],
      [0x8827, { name: "ISOSpeedRatings", desc: "ISO speed used for this image." }],
      [0x9003, { name: "DateTimeOriginal", desc: "Date and time when the original image data was generated." }],
      [0x9004, { name: "DateTimeDigitized", desc: "Date and time when the image was digitized." }],
      [0x9202, { name: "ApertureValue", desc: "Lens aperture value, often log2-scaled representation." }],
      [0x9207, { name: "MeteringMode", desc: "Metering mode used by the camera (e.g., center-weighted, spot)." }],
      [0x9209, { name: "Flash", desc: "Flash status and mode for this shot." }],
      [0x920a, { name: "FocalLength", desc: "Actual focal length of the lens, in millimeters." }],
      [0x9290, { name: "SubSecTime", desc: "Fractional seconds for DateTime." }],
      [0x9291, { name: "SubSecTimeOriginal", desc: "Fractional seconds for DateTimeOriginal." }],
      [0x9292, { name: "SubSecTimeDigitized", desc: "Fractional seconds for DateTimeDigitized." }],
      [0xa001, { name: "ColorSpace", desc: "Color space information (1 = sRGB, 0xFFFF = uncalibrated)." }],
      [0xa002, { name: "PixelXDimension", desc: "Valid image width in pixels." }],
      [0xa003, { name: "PixelYDimension", desc: "Valid image height in pixels." }],
      [0xa005, { name: "InteroperabilityIFDPointer", desc: "Offset to interoperability IFD." }],
      [0xa217, { name: "SensingMethod", desc: "Type of image sensor (e.g., one-chip color area sensor)." }],
      [0xa402, { name: "ExposureMode", desc: "Exposure mode (auto, manual, auto bracket)." }],
      [0xa403, { name: "WhiteBalance", desc: "White balance setting (auto, manual)." }],
      [0xa405, { name: "FocalLengthIn35mmFilm", desc: "Equivalent focal length in 35mm film." }],
      [0xa406, { name: "SceneCaptureType", desc: "Scene type (standard, landscape, portrait, night scene, etc.)." }],
      [0x0005, { name: "GPSAltitudeRef", desc: "Altitude reference: 0 = above sea level, 1 = below sea level." }],
      [0x0007, { name: "GPSTimeStamp", desc: "UTC time of image creation (hour, minute, second)." }],
      [0x001d, { name: "GPSDateStamp", desc: "UTC date of image creation." }]
    ]);

    out.push("<h4>All EXIF tags</h4>");
    out.push('<table class="byteView"><thead><tr>');
    out.push("<th>IFD</th><th>Tag</th><th>Name</th><th>Type</th><th>Count</th><th>Preview</th>");
    out.push("</tr></thead><tbody>");
    raw.forEach((tag: ExifRawTag) => {
      const tagHex = toHex32(tag.tag, 4);
      const info = TAG_INFO.get(tag.tag);
      const name = info ? info.name : "";
      const desc = info?.desc ? escapeHtml(info.desc) : "";
      const nameCell = name
        ? `<td title="${desc}">${escapeHtml(name)}</td>`
        : "<td></td>";
      out.push("<tr>");
      out.push(`<td>${escapeHtml(tag.ifd || "")}</td>`);
      out.push(`<td title="${tagHex}">${tagHex}</td>`);
      out.push(nameCell);
      out.push(`<td>${tag.type}</td>`);
      out.push(`<td>${tag.count}</td>`);
      out.push(`<td>${escapeHtml(tag.preview || "")}</td>`);
      out.push("</tr>");
    });
    out.push("</tbody></table>");
  }

  return out.join("");
}
