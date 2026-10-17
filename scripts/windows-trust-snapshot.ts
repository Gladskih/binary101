import { readFile } from "node:fs/promises";
import { normalizeAuthenticodeTrustStore } from "../analyzers/pe/authenticode/trust-store.js";

const snapshotProblem = async (path: string): Promise<string | null> => {
  try {
    const snapshot = normalizeAuthenticodeTrustStore(JSON.parse((await readFile(path)).toString()));
    if (!snapshot.generatedAt || !Number.isFinite(Date.parse(snapshot.generatedAt))) {
      return "The Windows trust snapshot has no valid generation date.";
    }
    if (!snapshot.source?.trim()) return "The Windows trust snapshot has no source.";
    if (!snapshot.trustedCAs.length) return "The Windows trusted root list is empty.";
    if ([...snapshot.trustedCAs, ...snapshot.revokedCAs].some(certificate => !certificate.derBase64)) {
      return "The Windows trust snapshot contains certificates without DER data.";
    }
    return snapshot.warnings?.length ? snapshot.warnings.join("; ") : null;
  } catch (error) {
    return String(error);
  }
};

export const ensureWindowsTrustSnapshot = async (
  path: string, platform: string, generateSnapshot: () => Promise<void>
): Promise<void> => {
  const problem = await snapshotProblem(path);
  if (!problem) return;
  if (platform !== "win32") {
    throw new Error(`${problem} Generate the snapshot on Windows with ` +
      `scripts/dump-windows-authenticode-trust.ps1 -OutputPath "${path}", ` +
      `or copy the windows-authenticode-trust CI artifact to that path.`);
  }
  console.warn(`Preparing Windows Authenticode trust snapshot: ${problem}`);
  await generateSnapshot();
  const generatedProblem = await snapshotProblem(path);
  if (generatedProblem) throw new Error(`Generated Windows trust snapshot is invalid: ${generatedProblem}`);
};
