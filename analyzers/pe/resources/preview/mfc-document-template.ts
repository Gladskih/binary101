export interface MfcDocumentTemplate {
  windowTitle: string;
  documentName: string;
  newName: string;
  filter: string;
  extension: string;
  registryId: string;
  registryName: string;
}

export const readMfcDocumentTemplate = (text: string): MfcDocumentTemplate | null => {
  // CDocTemplate resource strings contain up to seven LF-separated substrings.
  // Shape alone is evidence of an MFC convention, never proof of runtime use.
  // https://learn.microsoft.com/en-us/cpp/mfc/reference/cdoctemplate-class#cdoctemplate
  const parts = text.split("\n");
  if (parts.length < 5 || parts.length > 7 || !/^\.[^\\/:*?"<>|\s]+$/u.test(parts[4] ?? "")) return null;
  return { windowTitle: parts[0]!, documentName: parts[1]!, newName: parts[2]!, filter: parts[3]!,
    extension: parts[4]!, registryId: parts[5] ?? "", registryName: parts[6] ?? "" };
};
