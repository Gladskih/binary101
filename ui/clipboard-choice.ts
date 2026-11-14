import type { ClipboardEntry } from "./clipboard-snapshot.js";
import { formatHumanSize } from "../binary-utils.js";

const entryType = (entry: ClipboardEntry): string => {
  switch (entry.kind) {
    case "text": return entry.type || "Text (unspecified format)";
    case "file": return entry.file.type || "File (unspecified format)";
    case "handle": return entry.handle.kind === "directory" ? "Folder" : "File";
    case "unavailable": return entry.type || "Unavailable format";
  }
};

const entrySummary = (entry: ClipboardEntry): string => {
  switch (entry.kind) {
    case "text": return entry.text.length ? entry.text.slice(0, 160) : "Empty text";
    case "file": return entry.file.name;
    case "handle": return entry.handle.name;
    case "unavailable": return entry.error;
  }
};

const appendChoice = (
  body: HTMLTableSectionElement, entry: ClipboardEntry, select: () => void
): void => {
  const row = body.insertRow();
  const action = row.insertCell();
  row.insertCell().textContent = entryType(entry);
  const preview = row.insertCell();
  preview.className = "clipboardChoice__preview";
  preview.textContent = entrySummary(entry);
  const size = row.insertCell();
  size.className = "peNumeric";
  size.textContent = entry.kind === "file" ? formatHumanSize(entry.file.size) :
    entry.kind === "text" ? `${entry.text.length} characters` : "—";
  const button = action.appendChild(body.ownerDocument.createElement("button"));
  button.type = "button";
  button.className = "tableButton";
  button.textContent = "Analyze";
  button.setAttribute("aria-label", `Analyze ${entryType(entry)}: ${entrySummary(entry)}`);
  button.disabled = entry.kind === "unavailable";
  button.addEventListener("click", select);
};

export const chooseClipboardEntries = (
  entries: readonly ClipboardEntry[]
): Promise<readonly ClipboardEntry[]> => {
  const previous = document.getElementById("clipboardChoice");
  if (previous instanceof HTMLDialogElement) previous.close();
  if (entries.length < 2) return Promise.resolve(entries);
  const dialog = document.createElement("dialog");
  dialog.id = "clipboardChoice";
  dialog.className = "clipboardChoice";
  dialog.setAttribute("aria-labelledby", "clipboardChoiceTitle");
  dialog.innerHTML = `<h2 id="clipboardChoiceTitle" tabindex="-1" autofocus>` +
    `Clipboard contents</h2>` +
    `<p>Choose what to analyze. Different formats may represent the same copied content.</p>` +
    `<div class="tableWrap"><table class="table"><thead><tr>` +
    `<th scope="col">Action</th><th scope="col">Type</th>` +
    `<th scope="col">Name or preview</th>` +
    `<th scope="col" class="peNumeric">Size</th>` +
    `</tr></thead><tbody></tbody>` +
    `</table></div><div class="clipboardChoice__actions">` +
    `<button type="button" class="tableButton">Cancel</button></div>`;
  return new Promise(resolve => {
    let selected: readonly ClipboardEntry[] = [];
    const select = (choices: readonly ClipboardEntry[]): void => {
      selected = choices;
      dialog.close();
    };
    entries.forEach(entry => appendChoice(dialog.querySelector("tbody")!, entry,
      () => select([entry])));
    const files = entries.filter(entry => entry.kind === "file" || entry.kind === "handle");
    if (files.length > 1) {
      const all = document.createElement("button");
      all.type = "button";
      all.className = "tableButton";
      all.textContent = "Browse all files and folders";
      all.addEventListener("click", () => select(files));
      dialog.querySelector(".clipboardChoice__actions")!.prepend(all);
    }
    dialog.querySelector(".clipboardChoice__actions button:last-child")!
      .addEventListener("click", () => select([]));
    dialog.addEventListener("close", () => { dialog.remove(); resolve(selected); }, { once: true });
    document.body.append(dialog);
    dialog.showModal();
  });
};
