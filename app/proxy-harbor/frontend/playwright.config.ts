import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests', testMatch: '**/*.spec.ts', fullyParallel: false, workers: 1, timeout: 45_000,
  use: { baseURL: 'http://127.0.0.1:19345', channel: 'msedge', headless: true,
    viewport: { width: 1280, height: 950 }, screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  webServer: { command: 'node ../scripts/e2e-server.mjs', url: 'http://127.0.0.1:19345',
    reuseExistingServer: false, timeout: 30_000 },
})
