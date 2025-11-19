"use strict";

const MAX_XREF_ENTRIES = 20000;
const MAX_OBJECT_SCAN = 65536;

const decoder = new TextDecoder("latin1", { fatal: false });

function parseHeader(text, issues) {
  const firstLineEnd = text.indexOf("\n");
  const headerLine =
    firstLineEnd !== -1 ? text.slice(0, firstLineEnd).trimEnd() : text.trimEnd();
  const match = headerLine.match(/^%PDF-([0-9]+\.[0-9]+)/);
  if (!match) {
    issues.push("Missing or malformed %PDF- header.");
    return { headerLine, version: null };
  }
  const binaryMarker = text.slice(0, 256).match(/%[^\n]{4,}/);
  return { headerLine, version: match[1], binaryMarker: binaryMarker ? binaryMarker[0] : null };
}

function parseStartxref(text, issues) {
  const idx = text.lastIndexOf("startxref");
  if (idx === -1) {
    issues.push("startxref marker not found.");
    return null;
  }
  const tail = text.slice(idx);
  const match = tail.match(/startxref\s+([0-9]+)/);
  if (!match) {
    issues.push("startxref present but offset is unreadable.");
    return null;
  }
  return Number.parseInt(match[1], 10);
}

function skipWhitespace(text, position) {
  let pos = position;
  while (pos < text.length && /\s/.test(text[pos])) pos += 1;
  return pos;
}

function parseXrefTable(text, startOffset, issues) {
  let pos = skipWhitespace(text, startOffset);
  if (!text.startsWith("xref", pos)) return null;
  pos += 4;
  const tableBody = text.slice(pos);
  const trailerIndex = tableBody.indexOf("trailer");
  if (trailerIndex === -1) {
    issues.push("xref table found without trailer.");
    return null;
  }
  const lines = tableBody.slice(0, trailerIndex).split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const sections = [];
  const entries = [];
  let lineIndex = 0;
  while (lineIndex < lines.length) {
    const headerParts = lines[lineIndex].split(/\s+/);
    if (headerParts.length < 2) {
      issues.push("xref subsection header is malformed.");
      break;
    }
    const startObj = Number.parseInt(headerParts[0], 10);
    const count = Number.parseInt(headerParts[1], 10);
    if (Number.isNaN(startObj) || Number.isNaN(count)) {
      issues.push("xref subsection uses non-numeric bounds.");
      break;
    }
    lineIndex += 1;
    sections.push({ start: startObj, count });
    for (let i = 0; i < count; i += 1) {
      if (lineIndex >= lines.length) {
        issues.push("xref subsection truncated before expected entry count.");
        break;
      }
      const entryLine = lines[lineIndex];
      const entryMatch = entryLine.match(/^(\d{10})\s+(\d{5})\s+([fn])/);
      if (!entryMatch) {
        issues.push(`xref entry ${startObj + i} is malformed.`);
        lineIndex += 1;
        continue;
      }
      const objectNumber = startObj + i;
      entries.push({
        objectNumber,
        offset: Number.parseInt(entryMatch[1], 10),
        generation: Number.parseInt(entryMatch[2], 10),
        inUse: entryMatch[3] === "n"
      });
      lineIndex += 1;
      if (entries.length >= MAX_XREF_ENTRIES) {
        issues.push("xref entry limit reached; further entries are omitted.");
        return { kind: "table", startOffset, sections, entries, trailerText: null };
      }
    }
  }
  const trailerText = tableBody.slice(trailerIndex + "trailer".length).trimStart();
  return { kind: "table", startOffset, sections, entries, trailerText };
}

function extractDictionary(text, startAt) {
  const dictStart = text.indexOf("<<", startAt);
  if (dictStart === -1) return null;
  let depth = 0;
  for (let i = dictStart; i < text.length - 1; i += 1) {
    const pair = text.slice(i, i + 2);
    if (pair === "<<") {
      depth += 1;
      i += 1;
      continue;
    }
    if (pair === ">>") {
      depth -= 1;
      i += 1;
      if (depth === 0) return text.slice(dictStart, i + 1);
    }
  }
  return null;
}

function parseIndirectRef(dictText, name) {
  const pattern = new RegExp(`/${name}\\s+(\\d+)\\s+(\\d+)\\s+R`);
  const match = dictText.match(pattern);
  if (!match) return null;
  return { objectNumber: Number.parseInt(match[1], 10), generation: Number.parseInt(match[2], 10) };
}

function parseTrailerDictionary(trailerText) {
  const dict = extractDictionary(trailerText, 0);
  if (!dict) return { raw: trailerText.trim(), size: null, rootRef: null, infoRef: null, id: null };
  const sizeMatch = dict.match(/\/Size\s+(\d+)/);
  const idMatch = dict.match(/\/ID\s*\[\s*<([^>]+)>\s*<([^>]+)>\s*\]/);
  return {
    raw: dict.trim(),
    size: sizeMatch ? Number.parseInt(sizeMatch[1], 10) : null,
    rootRef: parseIndirectRef(dict, "Root"),
    infoRef: parseIndirectRef(dict, "Info"),
    id: idMatch ? [idMatch[1], idMatch[2]] : null
  };
}

function parseXrefStream(text, startOffset, issues) {
  const pos = skipWhitespace(text, startOffset);
  const objectMatch = text.slice(pos, pos + 64).match(/(\d+)\s+(\d+)\s+obj/);
  if (!objectMatch) return null;
  const dict = extractDictionary(text, pos);
  if (!dict || dict.indexOf("/XRef") === -1) return null;
  issues.push("Cross-reference stream detected; detailed entries are not decoded yet.");
  return {
    kind: "stream",
    startOffset,
    objectNumber: Number.parseInt(objectMatch[1], 10),
    generation: Number.parseInt(objectMatch[2], 10),
    trailer: parseTrailerDictionary(dict)
  };
}

function parseXref(text, startOffset, issues) {
  if (startOffset == null || Number.isNaN(startOffset)) return null;
  if (startOffset < 0 || startOffset >= text.length) {
    issues.push("startxref offset points outside the file.");
    return null;
  }
  const table = parseXrefTable(text, startOffset, issues);
  if (table) {
    const trailer = parseTrailerDictionary(table.trailerText || "");
    return { ...table, trailer };
  }
  const stream = parseXrefStream(text, startOffset, issues);
  if (stream) return stream;
  issues.push("Unable to read cross-reference information at startxref offset.");
  return null;
}

function buildOffsetMap(xref) {
  if (!xref || xref.kind !== "table") return null;
  const map = new Map();
  xref.entries
    .filter(e => e.inUse)
    .forEach(entry => map.set(entry.objectNumber, entry.offset));
  return map;
}

function readObjectText(text, offset, issues, label) {
  if (offset == null || offset < 0 || offset >= text.length) {
    issues.push(`${label} offset is outside the file.`);
    return null;
  }
  const slice = text.slice(offset, offset + MAX_OBJECT_SCAN);
  const endIdx = slice.indexOf("endobj");
  if (endIdx === -1) {
    issues.push(`${label} object does not terminate with endobj near offset ${offset}.`);
    return null;
  }
  return slice.slice(0, endIdx);
}

function decodeLiteralString(value) {
  return value
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\b/g, "\b")
    .replace(/\\f/g, "\f")
    .replace(/\\\(/g, "(")
    .replace(/\\\)/g, ")")
    .replace(/\\\\/g, "\\");
}

function parseInfoDictionary(dictText) {
  if (!dictText) return null;
  const dict = extractDictionary(dictText, 0);
  if (!dict) return null;
  const parseField = name => {
    const match = dict.match(new RegExp(`/${name}\\s*\(([^)]*)\)`));
    return match ? decodeLiteralString(match[1]) : null;
  };
  return {
    raw: dict.trim(),
    title: parseField("Title"),
    author: parseField("Author"),
    subject: parseField("Subject"),
    keywords: parseField("Keywords"),
    creator: parseField("Creator"),
    producer: parseField("Producer"),
    creationDate: parseField("CreationDate"),
    modDate: parseField("ModDate")
  };
}

function parseCatalogDictionary(dictText) {
  if (!dictText) return null;
  const dict = extractDictionary(dictText, 0);
  if (!dict) return null;
  const pagesRef = parseIndirectRef(dict, "Pages");
  const namesRef = parseIndirectRef(dict, "Names");
  const outlinesRef = parseIndirectRef(dict, "Outlines");
  return { raw: dict.trim(), pagesRef, namesRef, outlinesRef };
}

function parsePagesDictionary(dictText) {
  if (!dictText) return null;
  const dict = extractDictionary(dictText, 0);
  if (!dict) return null;
  const countMatch = dict.match(/\/Count\s+(\d+)/);
  return { raw: dict.trim(), count: countMatch ? Number.parseInt(countMatch[1], 10) : null };
}

export async function parsePdf(file) {
  const buffer = await file.arrayBuffer();
  const text = decoder.decode(buffer);
  const issues = [];
  const header = parseHeader(text, issues);
  const startxref = parseStartxref(text, issues);
  const xref = parseXref(text, startxref, issues);
  const trailer = xref && xref.trailer ? xref.trailer : null;
  const offsets = buildOffsetMap(xref);

  let info = null;
  let catalog = null;
  let pages = null;

  if (offsets && trailer && trailer.infoRef) {
    const infoOffset = offsets.get(trailer.infoRef.objectNumber);
    const infoText = readObjectText(text, infoOffset, issues, "Info");
    info = parseInfoDictionary(infoText);
  }

  if (offsets && trailer && trailer.rootRef) {
    const rootOffset = offsets.get(trailer.rootRef.objectNumber);
    const catalogText = readObjectText(text, rootOffset, issues, "Catalog");
    catalog = parseCatalogDictionary(catalogText);
    if (catalog && catalog.pagesRef) {
      const pagesOffset = offsets.get(catalog.pagesRef.objectNumber);
      const pagesText = readObjectText(text, pagesOffset, issues, "Pages");
      pages = parsePagesDictionary(pagesText);
    }
  }

  return {
    size: buffer.byteLength,
    header,
    startxref,
    xref,
    trailer,
    info,
    catalog,
    pages,
    issues
  };
}
