"use strict";

import { hex } from "../binary-utils.js";
import type { ParseForUiResult } from "../analyzers/index.js";
import type { PeParseResult } from "../analyzers/pe/index.js";

const PE_SIGNATURE_SIZE = 4;
const COFF_HEADER_SIZE = 20;
const OPTIONAL_HEADER_CHECKSUM_OFFSET = 0x40;
const CHECKSUM_FIELD_SIZE = 4;
const CHECKSUM_BUTTON_ID = "peChecksumValidateButton";
const CHECKSUM_STATUS_ID = "peChecksumStatus";
const CHECKSUM_COMPUTED_ID = "peChecksumComputed";
const CHECKSUM_ZERO_NOTE =
  "Note: stored CheckSum is 0. Windows validates this field only for drivers, boot-loaded DLLs, and critical system DLLs.";
const CHECKSUM_AUTHENTICODE_NOTE =
  "Note: file contains an Authenticode certificate. The PE CheckSum includes certificates and can change after signing, so the stored value may be stale.";

type PeChecksumComputation = {
  checksum: number | null;
  warnings: string[];
};

type PeChecksumDeps = {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
};

const resolveChecksumOffset = (pe: PeParseResult): number | null => {
  const baseOffset = pe.dos?.e_lfanew;
  if (!Number.isFinite(baseOffset)) return null;
  const offset = baseOffset + PE_SIGNATURE_SIZE + COFF_HEADER_SIZE + OPTIONAL_HEADER_CHECKSUM_OFFSET;
  if (!Number.isSafeInteger(offset) || offset < 0) return null;
  return offset;
};

const computePeChecksum = async (
  file: File,
  checksumOffset: number
): Promise<PeChecksumComputation> => {
  const warnings: string[] = [];
  if (!Number.isFinite(checksumOffset) || checksumOffset < 0) {
    warnings.push("Checksum offset is invalid.");
    return { checksum: null, warnings };
  }
  if (checksumOffset % 4 !== 0) {
    warnings.push("Checksum offset is not dword aligned.");
    return { checksum: null, warnings };
  }
  if (checksumOffset + CHECKSUM_FIELD_SIZE > file.size) {
    warnings.push("Checksum field is outside the file bounds.");
    return { checksum: null, warnings };
  }

  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const byteLength = bytes.length;
  const remainder = byteLength % 2;
  const paddedLength = remainder ? byteLength + 1 : byteLength;
  const checksumWordIndex = checksumOffset / 2;
  const checksumWordIndex2 = checksumWordIndex + 1;
  let checksum = 0;

  for (let offset = 0; offset < paddedLength; offset += 2) {
    const index = offset / 2;
    if (index === checksumWordIndex || index === checksumWordIndex2) continue;

    let word = 0;
    if (offset + 2 <= byteLength) {
      word = bytes[offset]! | (bytes[offset + 1]! << 8);
    } else {
      word = offset < byteLength ? bytes[offset]! : 0;
    }

    checksum += word;
    checksum = (checksum & 0xffff) + (checksum >>> 16);
  }

  // PE checksum algorithm: sum 16-bit words, fold, then add original file length.
  checksum = checksum & 0xffff;

  return { checksum: (checksum + byteLength) >>> 0, warnings };
};

const createPeChecksumClickHandler =
  ({ getParseResult, getFile, setStatusMessage }: PeChecksumDeps) =>
  async (event: Event): Promise<void> => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    if (target.id !== CHECKSUM_BUTTON_ID) return;

    const file = getFile();
    if (!file) {
      setStatusMessage("No file selected.");
      return;
    }

    const parseResult = getParseResult();
    if (parseResult.analyzer !== "pe" || !parseResult.parsed) {
      setStatusMessage("Not a PE file.");
      return;
    }

    const statusElement = document.getElementById(CHECKSUM_STATUS_ID);
    const computedElement = document.getElementById(CHECKSUM_COMPUTED_ID);
    if (!(statusElement instanceof HTMLElement) || !(computedElement instanceof HTMLElement)) {
      setStatusMessage("Checksum UI is not available.");
      return;
    }

    const button = target as HTMLElement & { disabled?: boolean };
    const originalText = button.textContent || "Validate CheckSum";
    button.textContent = "Working...";
    if ("disabled" in button) {
      button.disabled = true;
    }

    try {
      const checksumOffset = resolveChecksumOffset(parseResult.parsed);
      if (checksumOffset == null) {
        statusElement.textContent = "Checksum offset is unavailable.";
        computedElement.textContent = "-";
        button.textContent = "Retry CheckSum";
        return;
      }

      const { checksum, warnings } = await computePeChecksum(file, checksumOffset);
      if (checksum == null) {
        statusElement.textContent = warnings.join(" ") || "Unable to compute checksum.";
        computedElement.textContent = "-";
        button.textContent = "Retry CheckSum";
        return;
      }

      const stored = parseResult.parsed.opt.CheckSum >>> 0;
      const statusParts = [
        checksum === stored ? "Matches stored value." : "Does not match stored value."
      ];
      if (stored === 0) {
        statusParts.push(CHECKSUM_ZERO_NOTE);
      }
      if (checksum !== stored && parseResult.parsed.hasCert) {
        statusParts.push(CHECKSUM_AUTHENTICODE_NOTE);
      }
      statusElement.textContent = statusParts.join(" ");
      computedElement.textContent = hex(checksum, 8);
      button.textContent = "Re-validate CheckSum";
    } catch (error) {
      const message = error instanceof Error && error.message ? error.message : String(error);
      statusElement.textContent = `Checksum failed: ${message}`;
      computedElement.textContent = "-";
      button.textContent = "Retry CheckSum";
    } finally {
      if ("disabled" in button) {
        button.disabled = false;
      }
      if (button.textContent === "Working...") {
        button.textContent = originalText;
      }
    }
  };

export { computePeChecksum, createPeChecksumClickHandler };
