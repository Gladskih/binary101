import { formatAccessError, getDroppedFileSystemHandles } from "./directory-handles.js";
import type { BrowserFileSystemHandle, DirectoryDropItem } from "./directory-handles.js";

export type ClipboardEntry =
  | { kind: "text"; type: string; text: string }
  | { kind: "file"; file: File }
  | { kind: "handle"; handle: BrowserFileSystemHandle }
  | { kind: "unavailable"; type: string; error: string };

export interface ClipboardDataItem extends DirectoryDropItem {
  type?: string;
  getAsString?: (callback: (text: string) => void) => void;
  getAsFile?: () => File | null;
}

const captureEntry = async (
  item: ClipboardDataItem, fallback?: File
): Promise<ClipboardEntry> => {
  try {
    if (item.kind === "string" && item.getAsString) {
      return { kind: "text", type: item.type ?? "",
        text: await new Promise<string>(resolve => item.getAsString!(resolve)) };
    }
    if (item.kind === "file") {
      const file = item.getAsFile?.() ?? fallback;
      const [handle] = await getDroppedFileSystemHandles({ length: 1, item: () => item });
      if (handle?.kind === "directory") return { kind: "handle", handle };
      if (file) return { kind: "file", file };
      if (handle) return { kind: "handle", handle };
    }
    return { kind: "unavailable", type: item.type ?? item.kind,
      error: "The browser did not provide readable data for this item." };
  } catch (error) {
    return { kind: "unavailable", type: item.type ?? item.kind,
      error: formatAccessError(error) };
  }
};

// Start all reads in the paste event, before its clipboard data store becomes inaccessible.
// https://www.w3.org/TR/clipboard-apis/#clipboard-event-interfaces
export const captureClipboardEntries = (
  items: readonly ClipboardDataItem[], files: readonly File[]
): Promise<ClipboardEntry[]> => {
  let fileIndex = 0;
  const pending = items.map(item => captureEntry(item,
    item.kind === "file" ? files[fileIndex++] : undefined));
  pending.push(...files.slice(fileIndex).map(file =>
    Promise.resolve<ClipboardEntry>({ kind: "file", file })));
  return Promise.all(pending);
};
