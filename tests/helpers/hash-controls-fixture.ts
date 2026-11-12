import assert from "node:assert/strict";
import { HASH_ALGORITHMS, type HashAlgorithmOption, type HashControls } from "../../ui/hash-controls.js";

// These fixtures implement only the DOM and File surfaces consumed by hash controls.

export const createHashControlsFixture = (label = "SHA-256"): {
  controls: HashControls;
  valueElement: HTMLElement;
  buttonElement: HTMLButtonElement;
  copyButtonElement: HTMLButtonElement;
  nativeHashBadgeElement: HTMLButtonElement;
} => {
  const valueElement = { textContent: "" } as HTMLElement;
  const buttonElement = {
    hidden: false,
    disabled: false,
    textContent: "Compute SHA-256"
  } as HTMLButtonElement;
  const copyButtonElement = { hidden: true } as HTMLButtonElement;
  const nativeHashBadgeElement = {
    ...buttonElement,
    textContent: "🍃",
    title: "",
    setAttribute: () => undefined
  };
  Object.defineProperties(nativeHashBadgeElement, {
    parentElement: { value: null },
    classList: { value: { add: () => undefined, remove: () => undefined } }
  });
  return {
    controls: { label, valueElement, buttonElement, copyButtonElement, nativeHashBadgeElement },
    valueElement,
    buttonElement,
    copyButtonElement,
    nativeHashBadgeElement
  };
};

export const createClipboardDigestText = (): string => {
  const bytes = new Uint8Array(8);
  bytes.forEach((_, index) => {
    bytes[index] = index;
  });
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
};

export const createHashValueElement = (textContent: string): HTMLElement =>
  ({ textContent }) as HTMLElement;

export const getHashAlgorithm = (id: string): HashAlgorithmOption => {
  const algorithm = HASH_ALGORITHMS.find(entry => entry.id === id);
  assert.ok(algorithm);
  return algorithm;
};

export const nodeDigestNameForHashAlgorithm = (algorithm: HashAlgorithmOption): string => {
  if (algorithm.id === "sha512224") return "sha512-224";
  if (algorithm.id === "sha512256") return "sha512-256";
  return algorithm.id;
};

export const createNativeHashFile = (bytes: Uint8Array<ArrayBuffer>): File => {
  const file = new File([bytes], "sample");
  Object.defineProperty(file, "stream", { value: () => {
    throw new Error("Native hash must not read a stream.");
  } });
  return file;
};

export const createFallbackHashFile = (bytes: Uint8Array<ArrayBuffer>): File => {
  const file = new File([bytes], "sample");
  Object.defineProperty(file, "arrayBuffer", { value: () => {
    throw new Error("Fallback hash must not read an ArrayBuffer.");
  } });
  return file;
};

export const installNativeDigestProbe = (): {
  algorithms: AlgorithmIdentifier[];
  restore: () => void;
} => {
  const globals = globalThis;
  const cryptoDescriptor = Object.getOwnPropertyDescriptor(globals, "crypto");
  const nativeDigest = crypto.subtle.digest.bind(crypto.subtle);
  const algorithms: AlgorithmIdentifier[] = [];
  Object.defineProperty(globals, "crypto", {
    configurable: true,
    value: {
      subtle: {
        digest: async (
          algorithm: AlgorithmIdentifier,
          data: BufferSource
        ): Promise<ArrayBuffer> => {
          algorithms.push(algorithm);
          return nativeDigest(algorithm, data);
        }
      }
    }
  });
  return {
    algorithms,
    restore: () => {
      if (cryptoDescriptor) Object.defineProperty(globals, "crypto", cryptoDescriptor);
    }
  };
};

export const installClipboardStub = (
  writeText: (text: string) => Promise<void>
): (() => void) => {
  const globals = globalThis;
  const hadNavigator = Object.prototype.hasOwnProperty.call(globals, "navigator");
  const originalNavigator = globals["navigator"];
  Object.defineProperty(globals, "navigator", {
    configurable: true,
    value: { clipboard: { writeText } }
  });
  return () => {
    if (hadNavigator) {
      Object.defineProperty(globals, "navigator", {
        configurable: true,
        value: originalNavigator
      });
      return;
    }
    Reflect.deleteProperty(globals, "navigator");
  };
};

export const clickFixture = (button: HTMLButtonElement): (() => void) => {
  let handler: EventListener | null = null;
  Object.defineProperty(button, "addEventListener", { value: (type: string, listener: EventListener) => {
    assert.equal(type, "click");
    assert.equal(typeof listener, "function");
    handler = listener;
  } });
  return () => { assert.ok(handler); handler(new Event("click")); };
};

export const nextText = (element: HTMLElement): Promise<string> => new Promise(resolve => {
  let text = element.textContent ?? "";
  Object.defineProperty(element, "textContent", { configurable: true,
    get: () => text, set: (value: string) => { text = value; resolve(value); } });
});
