import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  reporter: "list",
  webServer: {
    command: "npx http-server dist -a 127.0.0.1 -p 4173",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI
  },
  use: {
    headless: true,
    viewport: { width: 1280, height: 720 },
    baseURL: "http://127.0.0.1:4173"
  }
});
