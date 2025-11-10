"use strict";

// Generic utilities shared across modules

export const nowIso = () => new Date().toISOString();

export const humanSize = n => {
  const k = 1024, u = ["B","KB","MB","GB","TB"]; let i = 0; let v = n;
  while (v >= k && i < u.length - 1) { v /= k; i++; }
  const rounded = v >= 100 ? Math.round(v) : Math.round(v * 10) / 10;
  return `${rounded} ${u[i]} (${n} bytes)`;
};

export const hex = (n, w = 0) => "0x" + Number(n >>> 0).toString(16).padStart(w, "0");
export const hex64 = b => "0x" + b.toString(16);

export const safe = s => String(s).replace(/"/g, "&quot;").replace(/</g, "&lt;");

export const dd = (k, v, t) => `<dt${t ? ` title="${safe(t)}"` : ""}>${k}</dt><dd>${v}</dd>`;

export const rowOpts = (sel, opts) => `<div class="optionsRow">${opts.map(([c, l]) => `
  <span class="opt ${c === sel ? "sel" : "dim"}" title="${safe(l + " (" + hex(c, 4) + ")")}">${l}</span>`).join("")}
  </div>`;

export const rowFlags = (mask, flags) => `<div class="optionsRow">${flags.map(([b, n, tip]) => `
  <span class="opt ${mask & b ? "sel" : "dim"}" title="${safe((tip ? `${n} — ${tip}` : n) + " (" + hex(b, 4) + ")")}">${n}</span>`).join("")}
  </div>`;

export const isoOrDash = sec => {
  if (!Number.isFinite(sec) || sec <= 0) return "-";
  const d = new Date(sec * 1000);
  const y = d.getUTCFullYear();
  const s = d.toISOString();
  return (y < 1990 || y > 2100) ? (s + " (unusual)") : s;
};

// Binary helpers
export const ascii = (dv, off, len) => {
  let s = "";
  for (let i = 0; i < len && off + i < dv.byteLength; i++) {
    const c = dv.getUint8(off + i);
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
};

export const printable = b => b >= 0x20 && b <= 0x7e;

export const runStrings = (u8, min) => {
  const out = []; let s = "";
  for (const b of u8) {
    if (printable(b)) {
      s += String.fromCharCode(b);
      if (s.length > 4096) { out.push(s); s = ""; }
    } else { if (s.length >= min) out.push(s); s = ""; }
  }
  if (s.length >= min) out.push(s);
  return out;
};

export const bufToHex = ab => [...new Uint8Array(ab)].map(b => b.toString(16).padStart(2, "0")).join("");

export const alignUp = (x, a) => {
  if (!a) return x >>> 0;
  const m = (a - 1) >>> 0;
  return ((x + m) & ~m) >>> 0;
};

