import { defineConfig } from '@playwright/test';

const apiPort = 8090;
const sitePort = 4173;
const apiURL = `http://api.lds.test:${apiPort}`;
const siteURL = `http://app.lds.test:${sitePort}`;

export default defineConfig({
  testDir: './tests',
  globalTeardown: './global-teardown.mjs',
  workers: 1,
  timeout: 60_000,
  expect: {
    timeout: 10_000
  },
  use: {
    baseURL: siteURL,
    channel: 'chromium',
    trace: 'retain-on-failure',
    launchOptions: {
      args: [
        `--host-resolver-rules=MAP app.lds.test 127.0.0.1, MAP api.lds.test 127.0.0.1`,
        `--unsafely-treat-insecure-origin-as-secure=${siteURL},${apiURL}`
      ]
    }
  },
  webServer: [
    {
      command: `node frontend-server.mjs`,
      url: 'http://127.0.0.1:4173/editorial.html',
      reuseExistingServer: !process.env.CI,
      timeout: 30_000
    },
    {
      command: 'bash ./web-tests/run-api.sh',
      cwd: '..',
      url: `http://127.0.0.1:${apiPort}/readyz`,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      env: {
        ...process.env,
        APP_ENV: 'development',
        HTTP_ADDR: `:${apiPort}`,
        DATABASE_URL:
          process.env.DATABASE_URL ??
          'postgres://lds:lds_dev_password@127.0.0.1:5432/lds_user_service?sslmode=disable',
        CORS_ALLOWED_ORIGINS: siteURL,
        MAIL_OUTBOX_FILE: '/tmp/lds-user-service-browser-mail/outbox.jsonl',
        EMAIL_VERIFICATION_REQUIRED: 'true'
      }
    }
  ]
});
