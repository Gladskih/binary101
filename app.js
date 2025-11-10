"use strict";

import { nowIso, humanSize } from "./utils.js";
import { computeHashForFile, copyToClipboard } from "./hash.js";
import { detectBinaryType, parseForUi } from "./analyzers/index.js";
import { renderPe } from "./pe-render.js";

// DOM
const el = id => document.getElementById(id);
const dropZone = el("dropZone"), fileInput = el("fileInput"), statusMsg = el("statusMessage");
const card = el("fileInfoCard");
const nameTop = el("fileOriginalName"), sizeTop = el("fileSizeDisplay"), kindTop = el("fileKindDisplay");
const nameDet = el("fileNameDetail"), sizeDet = el("fileSizeDetail"), tsDet = el("fileTimestampDetail"), srcDet = el("fileSourceDetail"), kindDet = el("fileBinaryTypeDetail");
const peTerm = el("peDetailsTerm"), peVal = el("peDetailsValue");
const sha256Val = el("sha256Value"), sha512Val = el("sha512Value"), sha256Btn = el("sha256ComputeButton"), sha512Btn = el("sha512ComputeButton"), sha256Copy = el("sha256CopyButton"), sha512Copy = el("sha512CopyButton");

let currentFile = null;

// Status UI
const setStatus = m => { statusMsg.textContent = m || ""; };
const clearStatus = () => { statusMsg.textContent = ""; };

// Render dispatch
function renderIntoUi(analyzer, parsed) {
  if (!parsed) { peTerm.hidden = true; peVal.hidden = true; peVal.innerHTML = ""; return; }
  if (analyzer === "pe") {
    peTerm.textContent = "PE/COFF details";
    peTerm.hidden = false; peVal.hidden = false; peVal.innerHTML = renderPe(parsed);
  } else {
    peTerm.hidden = true; peVal.hidden = true; peVal.innerHTML = "";
  }
}

// Top-level flow
async function showFileInfo(file, source) {
  currentFile = file;
  const type = await detectBinaryType(file);
  const ts = nowIso(), sizeText = humanSize(file.size);

  nameTop.textContent = file.name || ""; sizeTop.textContent = sizeText; kindTop.textContent = type;
  nameDet.textContent = file.name || ""; sizeDet.textContent = sizeText; tsDet.textContent = ts; srcDet.textContent = source; kindDet.textContent = type;

  const { analyzer, parsed } = await parseForUi(file);
  renderIntoUi(analyzer, parsed);

  sha256Val.textContent = ""; sha512Val.textContent = "";
  sha256Copy.hidden = true; sha512Copy.hidden = true;
  sha256Btn.hidden = false; sha512Btn.hidden = false; sha256Btn.disabled = false; sha512Btn.disabled = false;
  sha256Btn.textContent = "Compute SHA-256"; sha512Btn.textContent = "Compute SHA-512";

  card.hidden = false;
  clearStatus();
}

// Input handlers
const handleFiles = files => {
  if (!files || files.length === 0) { setStatus("No file selected."); return; }
  if (files.length > 1) { setStatus("Multiple files are not supported yet."); return; }
  showFileInfo(files[0], "File selection");
};
["dragenter", "dragover"].forEach(t => dropZone.addEventListener(t, e => { e.preventDefault(); dropZone.classList.add("dragover"); }));
["dragleave", "drop"].forEach(t => dropZone.addEventListener(t, e => { e.preventDefault(); if (e.type === "drop") { const dt = e.dataTransfer; if (!dt) setStatus("Drop: cannot access data."); else { handleFiles(dt.files); } } dropZone.classList.remove("dragover"); }));
dropZone.addEventListener("keydown", e => { if (e.key === " " || e.key === "Enter") { e.preventDefault(); fileInput.click(); } });
fileInput.addEventListener("change", e => { const t = e.currentTarget; if (!(t instanceof HTMLInputElement)) return; handleFiles(t.files); t.value = ""; });
window.addEventListener("paste", async e => {
  const d = e.clipboardData; if (!d) { setStatus("Paste: clipboard not available."); return; }
  const files = [...d.files || []]; if (files.length === 1) { showFileInfo(files[0], "Paste (file)"); return; }
  const items = [...d.items || []].filter(it => it.kind === "string"); if (items.length !== 1) { setStatus("Paste: unsupported clipboard payload."); return; }
  const text = await new Promise(r => items[0].getAsString(r)); if (typeof text !== "string" || !text.length) { setStatus("Paste: empty text."); return; }
  const f = new File([text], "clipboard.bin", { type: "application/octet-stream" }); showFileInfo(f, "Paste (clipboard data)");
});

// Hashing UI
async function computeHash(algo, valEl, btnEl, copyEl) {
  if (!currentFile) { valEl.textContent = "No file selected."; return; }
  btnEl.disabled = true; btnEl.textContent = "Working...";
  try {
    const s = await computeHashForFile(currentFile, algo);
    valEl.textContent = s; copyEl.hidden = false; btnEl.hidden = true; clearStatus();
  } catch (err) {
    valEl.textContent = "Hash failed: " + String(err && err.name ? err.name + ": " : "") + String(err);
    btnEl.disabled = false; btnEl.textContent = "Retry"; copyEl.hidden = true;
  }
}
sha256Btn.addEventListener("click", () => computeHash("SHA-256", sha256Val, sha256Btn, sha256Copy));
sha512Btn.addEventListener("click", () => computeHash("SHA-512", sha512Val, sha512Btn, sha512Copy));
sha256Copy.addEventListener("click", async () => setStatus((await copyToClipboard(sha256Val.textContent || "")) ? "SHA-256 copied." : "Clipboard copy failed."));
sha512Copy.addEventListener("click", async () => setStatus((await copyToClipboard(sha512Val.textContent || "")) ? "SHA-512 copied." : "Clipboard copy failed."));

