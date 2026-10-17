import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  reporter: "list",
  webServer: {
    command: "npm run preview",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: false,
    // Preparing SDK metadata on a fresh checkout can take several minutes.
    timeout: 300_000
  },
  use: {
    headless: true,
    viewport: { width: 1280, height: 720 },
    baseURL: "http://127.0.0.1:4173"
  }
});
