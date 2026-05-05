"use strict";

type CertificateDownloadDeps = {
  setStatusMessage: (message: string | null | undefined) => void;
};

const sanitizeCertificateFilename = (name: string | null): string => {
  const raw = name?.split(/[\\/]/).pop()?.trim() || "certificate.cer";
  const safeName = raw.replace(/[^a-z0-9._-]+/gi, "_");
  return safeName.toLowerCase().endsWith(".cer") ? safeName : `${safeName}.cer`;
};

const base64ToBytes = (value: string): Uint8Array => {
  const normalized = value.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.length % 4 === 1) {
    throw new Error("Certificate DER data is not valid base64.");
  }
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
};

const triggerCertificateDownload = (bytes: Uint8Array, filename: string): void => {
  const der = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(der).set(bytes);
  const url = URL.createObjectURL(new Blob([der], { type: "application/pkix-cert" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

export const createCertificateDownloadClickHandler =
  ({ setStatusMessage }: CertificateDownloadDeps) =>
  (event: Event): void => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest("[data-certificate-download]");
    if (!(button instanceof HTMLElement)) return;
    const derBase64 = button.getAttribute("data-certificate-der-base64");
    if (!derBase64) {
      setStatusMessage("Certificate DER data is not available.");
      return;
    }
    try {
      triggerCertificateDownload(
        base64ToBytes(derBase64),
        sanitizeCertificateFilename(button.getAttribute("data-certificate-filename"))
      );
      setStatusMessage(null);
    } catch (error) {
      const message = error instanceof Error && error.message ? error.message : String(error);
      setStatusMessage(`Certificate download failed: ${message}`);
    }
  };
