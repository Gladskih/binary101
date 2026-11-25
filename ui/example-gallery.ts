import type { InspectionContext } from "./inspection-context.js";

const descriptions = [
  ["hello-msvc-x64.exe", "PE · C / MSVC", "x86-64, static CRT, imports and unwind records"],
  ["hello-masm-x86.exe", "PE · x86 assembly", "32-bit entry point, Win32 imports, no CRT"],
  ["hello-go-x64.exe", "PE · Go", "x86-64, Go build information and function table"],
  ["HelloCSharp.dll", "PE · C#", "CLR metadata, assembly references and managed methods"],
  ["hello-gcc-x64.elf", "ELF · C / GCC", "x86-64 PIE, dynamic linking, relocations and DWARF"],
  ["hello-go-arm64.elf", "ELF · Go", "AArch64, static linking and Go runtime metadata"],
  ["hello.wasm", "WebAssembly", "Host function import, exports, linear memory and data"],
  ["hello-samples.zip", "ZIP", "Stored and Deflate entries, sizes and extraction"],
  ["hello.sqlite", "SQLite", "Database header, table, index and schema records"],
  ["test-pattern.png", "PNG", "Lossless RGB image, chunk order and pixel dimensions"],
  ["test-pattern.jpg", "JPEG", "Baseline image, frame markers and quantization tables"],
  ["test-pattern.gif", "GIF", "Animation frames, palette and loop metadata"],
  ["hello.pdf", "PDF", "Cross-reference table, trailer and document information"],
  ["test-pattern.webm", "WebM", "VP8 video, Opus audio, keyframes and track metadata"]
] as const;

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
  const list = landing.querySelector("ul")!;
  const body = dialog.querySelector("tbody")!;
  const inspect = (file: File): Promise<void> => openFile(file, { source: "example", object: "file" });
  const welcome = createSamplePicker(landing.querySelector<HTMLElement>("[role=status]")!, inspect);
  const modal = createSamplePicker(dialog.querySelector<HTMLElement>("[role=status]")!, async file => {
    dialog.close();
    await inspect(file);
  }, () => dialog.open);
  for (const [name, label, description] of descriptions) {
    const url = assets[`../generated/gallery/${name}`];
    if (!url) continue;
    const row = body.insertRow();
    appendSampleButton(row.insertCell(), label, button => modal.select(url, name, button));
    row.insertCell().textContent = description;
    appendSampleButton(list.appendChild(document.createElement("li")), label,
      button => welcome.select(url, name, button)).title = description;
  }
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
