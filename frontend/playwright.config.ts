import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60000,
  reporter: 'list',
  outputDir: 'test-results',
  use: {
    baseURL: process.env.PS_E2E_BASE_URL ?? 'http://localhost:8080',
    channel: process.env.PS_E2E_BROWSER_CHANNEL,
    headless: true,
    viewport: { width: 1440, height: 1000 },
    // Authentication bodies must never be retained in test traces or recordings.
    trace: 'off',
    video: 'off',
    screenshot: 'off',
  },
});
