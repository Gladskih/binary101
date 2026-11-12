import { isPeWindowsParseResult, type PeParseResult } from "../../analyzers/pe/index.js";
import { humanSize } from "../../binary-utils.js";
import { overviewFact } from "../overview-card.js";
import { renderPeHeaderPreview } from "./header-preview.js";

const importPreview = (pe: PeParseResult): string => {
  if (!isPeWindowsParseResult(pe) || !pe.imports.entries.length) return "";
  const largest = pe.imports.entries.reduce((left, right) =>
    right.functions.length > left.functions.length ? right : left);
  return overviewFact("DLL with most imports", largest.dll || "(empty DLL name)") +
    overviewFact("Imports from this DLL", String(largest.functions.length)) +
    overviewFact("Total imports", `${pe.imports.entries.reduce((sum, entry) => sum + entry.functions.length, 0)}` +
      ` from ${pe.imports.entries.length} ` +
      (pe.imports.entries.length === 1 ? "DLL" : "DLLs"));
};

const exportPreview = (pe: PeParseResult): string => {
  if (!isPeWindowsParseResult(pe) || !pe.exports?.entries.length) return "";
  return overviewFact("DLL name", pe.exports.dllName || "(empty DLL name)") +
    overviewFact("Named exports", String(pe.exports.entries.reduce((sum, entry) => sum + entry.names.length, 0))) +
    overviewFact("Forwarded exports", String(pe.exports.entries.filter(entry => entry.forwarder).length));
};

const securityPreview = (pe: PeParseResult): string => {
  if (!isPeWindowsParseResult(pe) || !pe.security?.certs.length) return "";
  const checks = pe.security.certs.flatMap(certificate =>
    certificate.authenticode?.verification?.checks ?? []);
  const digest = checks.filter(check => check.id === "file-digest-match");
  return overviewFact("Embedded file digest", digest.length ?
    [...new Set(digest.map(check => check.status))].join(" · ") : "Not reported") +
    overviewFact("Recorded checks", `${checks.filter(check => check.status === "pass").length} pass · ` +
      `${checks.filter(check => check.status === "fail").length} fail · ` +
      `${checks.filter(check => check.status === "unknown").length} unknown`) +
    overviewFact("WIN_CERTIFICATE records", String(pe.security.certs.length));
};

const sectionPreview = (pe: PeParseResult): string => {
  if (!pe.sections.length) return "";
  const raw = pe.sections.reduce((left, right) =>
    right.sizeOfRawData > left.sizeOfRawData ? right : left);
  const virtual = pe.sections.reduce((left, right) =>
    right.virtualSize > left.virtualSize ? right : left);
  return overviewFact("Largest SizeOfRawData", `${raw.name.value} · ${humanSize(raw.sizeOfRawData)}`) +
    overviewFact("Largest VirtualSize", `${virtual.name.value} · ${humanSize(virtual.virtualSize)}`);
};

const directoryPreview = (pe: PeParseResult): string => {
  const present = pe.dirs.filter(directory => directory.rva || directory.size);
  if (!present.length) return "";
  const largest = present.reduce((left, right) => right.size > left.size ? right : left);
  return overviewFact("Largest directory", largest.name) +
    overviewFact("Size", humanSize(largest.size)) +
    overviewFact("Nonzero directory entries", String(present.length));
};

export const renderPeSectionPreview = (pe: PeParseResult, key: string): string => {
  if (key === "pe-headers") return renderPeHeaderPreview(pe);
  if (key === "security") return securityPreview(pe);
  if (key === "exports") return exportPreview(pe);
  if (key === "section-headers") return sectionPreview(pe);
  if (key === "data-directories") return directoryPreview(pe);
  return key === "imports" ? importPreview(pe) : "";
};
