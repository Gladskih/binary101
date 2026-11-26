import type { InspectionContext } from "./inspection-context.js";
import { exampleGroups } from "./example-catalog.js";

type FileOpener = (file: File, context: InspectionContext) => Promise<void>;

const fetchExample = async (url: string, name: string, signal: AbortSignal): Promise<File> => {
  const response = await fetch(url, { signal, headers: { Accept: "application/octet-stream" } });
  if (!response.ok || response.headers.get("content-type")?.startsWith("text/html")) {
    throw new Error(`Unexpected gallery response for ${name}.`);
  }
  const blob = await response.blob();
  if (!blob.size) throw new Error(`Gallery example ${name} is empty.`);
  return new File([blob], name, { type: blob.type });
};

const createSamplePicker = (
  status: HTMLElement, openFile: (file: File) => Promise<void>, isOpen: () => boolean = () => true
) => {
  let pending: { request: AbortController; button: HTMLButtonElement } | null = null;
  const clearPending = (): void => {
    pending?.button.removeAttribute("aria-disabled");
    pending = null;
  };
  const cancel = (): void => {
    pending?.request.abort();
    clearPending();
    status.textContent = "";
  };
  const select = async (url: string, name: string, button: HTMLButtonElement): Promise<void> => {
    if (pending) return;
    const request = new AbortController();
    pending = { request, button };
    button.setAttribute("aria-disabled", "true");
    status.textContent = `Loading ${name}…`;
    try {
      const file = await fetchExample(url, name, request.signal);
      if (request.signal.aborted || !isOpen()) return;
      status.textContent = "";
      await openFile(file);
    } catch {
      if (isOpen() && !request.signal.aborted) {
        status.textContent = `Unable to open ${name}. Try again.`;
      }
    } finally {
      if (pending?.request === request) clearPending();
    }
  };
  return { select, cancel };
};

const appendSampleButton = (
  parent: HTMLElement, label: string, select: (button: HTMLButtonElement) => Promise<void>
): HTMLButtonElement => {
  const button = parent.appendChild(parent.ownerDocument.createElement("button"));
  button.type = "button";
  button.className = "tableButton";
  button.textContent = label;
  button.addEventListener("click", () => { void select(button); });
  return button;
};

const bindGalleryDialog = (
  dialog: HTMLDialogElement, toolbar: HTMLElement, cancel: () => void
): void => {
  toolbar.hidden = false;
  toolbar.addEventListener("click", () => dialog.showModal());
  dialog.addEventListener("close", cancel);
  // The app listens for Paste and Drop globally, including while a dialog is open.
  for (const eventName of ["dragenter", "dragover", "dragleave", "drop", "paste"]) {
    dialog.addEventListener(eventName, event => {
      event.preventDefault();
      event.stopPropagation();
    });
  }
};

const appendWelcomeGroup = (parent: HTMLElement, caption: string): HTMLUListElement => {
  const document = parent.ownerDocument;
  const group = parent.appendChild(document.createElement("div"));
  group.appendChild(document.createElement("h3")).textContent = caption;
  const list = group.appendChild(document.createElement("ul"));
  list.className = "exampleGalleryLanding__examples";
  list.setAttribute("role", "list");
  return list;
};

const populateGallery = (
  groups: HTMLElement, body: HTMLTableSectionElement, assets: Record<string, string>,
  welcome: ReturnType<typeof createSamplePicker>, modal: ReturnType<typeof createSamplePicker>
): void => {
  for (const [caption, samples] of exampleGroups) {
    const entries = samples.flatMap(([name, label, description]) => {
      const url = assets[`../generated/gallery/${name}`];
      return url ? [{ name, label, description, url }] : [];
    });
    if (!entries.length) continue;
    const list = appendWelcomeGroup(groups, caption);
    for (const { name, label, description, url } of entries) {
      const row = body.insertRow();
      appendSampleButton(row.insertCell(), label, button => modal.select(url, name, button));
      row.insertCell().textContent = description;
      appendSampleButton(list.appendChild(groups.ownerDocument.createElement("li")), label,
        button => welcome.select(url, name, button)).title = description;
    }
  }
};

export const attachExampleGallery = (
  document: Document,
  openFile: FileOpener,
  // Only URL strings enter the bundle. The selected example is fetched on demand.
  assets = import.meta.glob<string>("../generated/gallery/*", {
    eager: true, query: "?url&no-inline", import: "default"
  })
): (() => void) => {
  const dialog = document.querySelector<HTMLDialogElement>("#exampleGallery")!;
  const landing = document.getElementById("galleryLanding")!;
  const body = dialog.querySelector("tbody")!;
  const inspect = (file: File): Promise<void> => openFile(file, { source: "example", object: "file" });
  const welcome = createSamplePicker(landing.querySelector<HTMLElement>("[role=status]")!, inspect);
  const modal = createSamplePicker(dialog.querySelector<HTMLElement>("[role=status]")!, async file => {
    dialog.close();
    await inspect(file);
  }, () => dialog.open);
  populateGallery(landing.querySelector<HTMLElement>(".exampleGalleryLanding__groups")!, body,
    assets, welcome, modal);
  if (body.rows.length) {
    landing.hidden = false;
    bindGalleryDialog(dialog, document.getElementById("galleryToolbarButton")!, modal.cancel);
  }
  return () => {
    welcome.cancel();
    modal.cancel();
    if (dialog.open) dialog.close();
  };
};
