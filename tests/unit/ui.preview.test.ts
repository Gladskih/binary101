"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { attachPreviewGuards, buildPreviewHtml, type PreviewRender } from "../../ui/preview.js";

type PreviewEnvironment = {
  createdBlobs: Blob[];
  restore: () => void;
};

const installPreviewEnvironment = (
  canPlayType: ((tagName: string, mimeType: string) => string) | null,
  objectUrl = "blob:preview"
): PreviewEnvironment => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const hadDocument = Object.prototype.hasOwnProperty.call(globals, "document");
  const originalDocument = globals["document"];
  const originalCreateObjectURL = URL.createObjectURL;
  const createdBlobs: Blob[] = [];

  if (canPlayType) {
    globals["document"] = {
      createElement(tagName: string) {
        return { canPlayType: (mimeType: string) => canPlayType(tagName, mimeType) };
      }
    };
  } else {
    Reflect.deleteProperty(globals, "document");
  }

  URL.createObjectURL = (blob: Blob): string => {
    createdBlobs.push(blob);
    return objectUrl;
  };

  return {
    createdBlobs,
    restore: () => {
      if (hadDocument) {
        globals["document"] = originalDocument;
      } else {
        Reflect.deleteProperty(globals, "document");
      }
      URL.createObjectURL = originalCreateObjectURL;
    }
  };
};

const createVideoGuardFixture = (): {
  container: HTMLElement;
  triggerSourceError: () => void;
} => {
  let sourceErrorListener: (() => void) | undefined;
  const parentElement = {
    removeChild(node: unknown) {
      assert.equal(node, wrapper);
    }
  };
  const wrapper = { parentElement } as HTMLElement;
  const sourceElement = {
    addEventListener(_type: string, listener: () => void) {
      sourceErrorListener = listener;
    }
  } as HTMLSourceElement;
  const videoElement = {
    isConnected: true,
    addEventListener() {},
    closest(selector: string) {
      return selector === ".videoPreview" ? wrapper : null;
    },
    querySelector(selector: string) {
      return selector === "source" ? sourceElement : null;
    }
  } as unknown as HTMLVideoElement;
  const container = {
    querySelector(selector: string) {
      return selector === ".videoPreview video" ? videoElement : null;
    }
  } as HTMLElement;

  return {
    container,
    triggerSourceError: () => {
      assert.ok(sourceErrorListener);
      sourceErrorListener();
    }
  };
};

const createAudioGuardFixture = (): {
  container: HTMLElement;
  triggerAudioError: () => void;
  setStatusMessage: (message: string | null | undefined) => void;
  statusMessages: Array<string | null | undefined>;
  wasRemoved: () => boolean;
} => {
  const statusMessages: Array<string | null | undefined> = [];
  let removed = false;
  let audioErrorListener: (() => void) | undefined;
  const wrapper = {
    parentElement: {
      removeChild(node: unknown) {
        assert.equal(node, wrapper);
        removed = true;
      }
    }
  } as HTMLElement;
  const audioElement = {
    isConnected: true,
    addEventListener(_type: string, listener: () => void) {
      audioErrorListener = listener;
    },
    closest(selector: string) {
      return selector === ".audioPreview" ? wrapper : null;
    }
  } as unknown as HTMLAudioElement;
  const container = {
    querySelector(selector: string) {
      return selector === ".audioPreview audio" ? audioElement : null;
    }
  } as HTMLElement;

  return {
    container,
    triggerAudioError: () => {
      assert.ok(audioErrorListener);
      audioErrorListener();
    },
    setStatusMessage: (message: string | null | undefined) => {
      statusMessages.push(message);
    },
    statusMessages,
    wasRemoved: () => removed
  };
};

void test("buildPreviewHtml returns null for a missing file and clears the preview URL", () => {
  const previewUrls: Array<string | null> = ["stale"];

  const preview = buildPreviewHtml({
    file: null,
    typeLabel: "image/png",
    setPreviewUrl: value => {
      previewUrls.push(value);
    }
  });

  assert.equal(preview, null);
  assert.deepEqual(previewUrls, ["stale", null]);
});

void test("buildPreviewHtml renders image previews with escaped alt text", () => {
  const environment = installPreviewEnvironment((_tagName, _mimeType) => "probably", "blob:image");
  const previewUrls: Array<string | null> = [];

  try {
    const preview = buildPreviewHtml({
      file: new File([new Uint8Array([1, 2, 3])], "cover<1>.png", { type: "image/png" }),
      typeLabel: "PNG image",
      setPreviewUrl: value => {
        previewUrls.push(value);
      }
    });

    assert.deepEqual(preview, {
      kind: "image",
      html: '<div class="jpegPreview"><img src="blob:image" alt="Preview of cover&lt;1>.png" /></div>'
    });
    assert.deepEqual(previewUrls, [null, "blob:image"]);
    assert.equal(environment.createdBlobs.length, 1);
  } finally {
    environment.restore();
  }
});

void test("buildPreviewHtml uses a label-derived video MIME when the primary MIME is unplayable", () => {
  const environment = installPreviewEnvironment(
    (_tagName, mimeType) => (mimeType === "video/mp4" ? "maybe" : "")
  );

  try {
    const preview = buildPreviewHtml({
      file: new File([new Uint8Array([0x01])], "clip.bin", { type: "video/mpeg" }),
      typeLabel: "MP4/QuickTime container (ISO-BMFF)",
      setPreviewUrl: () => {}
    });

    assert.deepEqual(preview, {
      kind: "video",
      html: [
        '<div class="videoPreview">',
        '<video controls preload="metadata" playsinline>',
        '<source src="blob:preview" type="video/mp4">',
        "Your browser cannot play this video inline: clip.bin.",
        "</video>",
        "</div>"
      ].join("")
    });
  } finally {
    environment.restore();
  }
});

void test("buildPreviewHtml renders audio previews when playability probes are unavailable", () => {
  const environment = installPreviewEnvironment(null, "blob:audio");

  try {
    const preview = buildPreviewHtml({
      file: new File([new Uint8Array([0x01])], "track.mp3", { type: "audio/mpeg" }),
      typeLabel: "MPEG audio stream (MP3/AAC)",
      setPreviewUrl: () => {}
    });

    assert.deepEqual(preview, {
      kind: "audio",
      html: [
        '<div class="audioPreview">',
        '<audio controls preload="metadata" src="blob:audio" type="audio/mpeg"></audio>',
        "</div>"
      ].join("")
    });
  } finally {
    environment.restore();
  }
});

void test("buildPreviewHtml returns null when the browser cannot play the candidate preview", () => {
  const environment = installPreviewEnvironment(() => "");
  const previewUrls: Array<string | null> = [];

  try {
    const preview = buildPreviewHtml({
      file: new File([new Uint8Array([0x01])], "clip.mpg", { type: "video/mpeg" }),
      typeLabel: "MPEG Program Stream (MPG)",
      setPreviewUrl: value => {
        previewUrls.push(value);
      }
    });

    assert.equal(preview, null);
    assert.deepEqual(previewUrls, [null]);
    assert.equal(environment.createdBlobs.length, 0);
  } finally {
    environment.restore();
  }
});

void test("attachPreviewGuards removes broken video previews and sets a status message", () => {
  const fixture = createVideoGuardFixture();
  const statusMessages: Array<string | null | undefined> = [];
  const preview: PreviewRender = { kind: "video", html: "" };

  attachPreviewGuards(preview, fixture.container, message => {
    statusMessages.push(message);
  });
  fixture.triggerSourceError();

  assert.deepEqual(statusMessages, [
    "Preview not shown: browser cannot play this video format inline."
  ]);
});

void test("attachPreviewGuards removes broken audio previews and sets a status message", () => {
  const fixture = createAudioGuardFixture();
  const preview: PreviewRender = { kind: "audio", html: "" };

  attachPreviewGuards(preview, fixture.container, fixture.setStatusMessage);
  fixture.triggerAudioError();

  assert.equal(fixture.wasRemoved(), true);
  assert.deepEqual(fixture.statusMessages, [
    "Preview not shown: browser cannot play this audio format inline."
  ]);
});

void test("attachPreviewGuards tolerates missing media elements", () => {
  const statusMessages: Array<string | null | undefined> = [];
  const container = {
    querySelector() {
      return null;
    }
  } as unknown as HTMLElement;

  attachPreviewGuards({ kind: "audio", html: "" }, container, message => {
    statusMessages.push(message);
  });

  assert.deepEqual(statusMessages, []);
});
