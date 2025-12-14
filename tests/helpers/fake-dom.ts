"use strict";

type GlobalDom = {
  document?: unknown;
  HTMLElement?: unknown;
  HTMLProgressElement?: unknown;
};

export class FakeHTMLElement {
  textContent: string | null = null;
  className = "";
  hidden = false;
  disabled = false;
}

export class FakeHTMLProgressElement extends FakeHTMLElement {
  max = 0;
  value = 0;
  removedAttributes: string[] = [];
  removeAttribute(name: string): void {
    this.removedAttributes.push(name);
  }
}

export const installFakeDom = (
  extraElements: Record<string, FakeHTMLElement> = {}
): {
  progress: FakeHTMLProgressElement;
  text: FakeHTMLElement;
  restore: () => void;
} => {
  const globals = globalThis as unknown as GlobalDom;
  const originalDocument = globals.document;
  const originalHTMLElement = globals.HTMLElement;
  const originalHTMLProgressElement = globals.HTMLProgressElement;

  globals.HTMLElement = FakeHTMLElement;
  globals.HTMLProgressElement = FakeHTMLProgressElement;

  const progress = new FakeHTMLProgressElement();
  const text = new FakeHTMLElement();
  globals.document = {
    getElementById: (id: string): unknown => {
      if (id === "peInstructionSetsProgress") return progress;
      if (id === "peInstructionSetsProgressText") return text;
      return extraElements[id] ?? null;
    }
  };
  return {
    progress,
    text,
    restore: () => {
      globals.document = originalDocument;
      globals.HTMLElement = originalHTMLElement;
      globals.HTMLProgressElement = originalHTMLProgressElement;
    }
  };
};

export const flushTimers = async (): Promise<void> => {
  await new Promise<void>(resolve => setTimeout(resolve, 0));
};
