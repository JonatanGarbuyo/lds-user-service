import { expect, test } from '@playwright/test';
import { createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const outbox = '/tmp/lds-user-service-browser-mail/outbox.jsonl';
const password = 'correct horse battery';

async function verificationCode(email) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const lines = (await readFile(outbox, 'utf8')).trim().split('\n').filter(Boolean);
      const message = lines
        .map((line) => JSON.parse(line))
        .filter((entry) => entry.to === email)
        .at(-1);
      if (message?.code) {
        return message.code;
      }
    } catch {
      // The outbox is created after the registration request.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`verification code for ${email} was not written to the outbox`);
}

function decodeSegment(segment) {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

test('site subdomain logs in through the service subdomain with a host-only cookie', async ({ page, context, request }) => {
  const email = `t03-browser-${Date.now()}@example.com`;

  const registration = await request.post('http://127.0.0.1:8090/v1/users', {
    data: { email, password }
  });
  expect(registration.status()).toBe(201);
  const user = await registration.json();
  expect(user.emailVerified).toBe(false);

  const confirmation = await request.post('http://127.0.0.1:8090/v1/auth/email-verification/confirm', {
    data: { email, code: await verificationCode(email) }
  });
  expect(confirmation.status()).toBe(200);
  expect((await confirmation.json()).emailVerified).toBe(true);

  await page.goto('/');
  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('#login');
  await expect(page.locator('#status')).toHaveText('200');

  const login = await page.evaluate(() => window.__loginResult);
  expect(login.status).toBe(200);
  expect(login.body.user.id).toBe(user.id);
  expect(login.body.user.email).toBe(email);
  expect(login.body.session.kind).toBe('web');
  expect(login.body.readerState.signedSnapshot.split('.')).toHaveLength(3);
  expect(login.body.csrfToken).toBeTruthy();

  const cookies = await context.cookies();
  const session = cookies.find((cookie) => cookie.name === 'lds_session');
  expect(session).toBeTruthy();
  expect(session.domain.replace(/^\./, '')).toBe('api.lds.test');
  expect(session.httpOnly).toBe(true);
  expect(session.secure).toBe(true);
  expect(session.sameSite).toBe('Lax');
  expect(session.expires).toBeGreaterThan(Date.now() / 1000 + 80 * 24 * 60 * 60);
  expect(JSON.stringify(login.body)).not.toContain(session.value);

  const visibleCookies = await page.evaluate(() => document.cookie);
  expect(visibleCookies).not.toContain('lds_session');
  expect(visibleCookies).not.toContain('lds_csrf');

  const me = await page.evaluate(() => window.fetchMe());
  expect(me.status).toBe(200);
  expect(me.body.id).toBe(user.id);
  expect(me.body.email).toBe(email);

  const snapshot = login.body.readerState.signedSnapshot;
  const [encodedHeader, encodedPayload, encodedSignature] = snapshot.split('.');
  const header = decodeSegment(encodedHeader);
  const payload = decodeSegment(encodedPayload);
  expect(header.alg).toBe('ES256');
  expect(payload.iss).toBe('lds-user-service');
  expect(payload.aud).toBe('lds-web');
  expect(payload.sub).toBe(user.id);
  expect(payload.emailVerified).toBe(true);
  expect(payload.exp * 1000).toBeGreaterThan(Date.now());

  const jwks = await page.evaluate(() => window.fetchJWKS());
  expect(jwks.status).toBe(200);
  const jwk = jwks.body.keys.find((candidate) => candidate.kid === header.kid);
  expect(jwk).toBeTruthy();
  const publicKey = createPublicKey({
    key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    format: 'jwk'
  });
  expect(
    verify(
      'sha256',
      Buffer.from(`${encodedHeader}.${encodedPayload}`),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(encodedSignature, 'base64url')
    )
  ).toBe(true);
});

test('public editorial HTML remains available without authentication', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const response = await page.goto('/editorial.html');

  expect(response.status()).toBe(200);
  expect(response.headers()['cache-control']).toBe('public, max-age=60');
  await expect(page.getByRole('heading', { name: 'Public editorial' })).toBeVisible();
  await expect(page.getByText('available without a session or Reader State snapshot')).toBeVisible();
  expect(await context.cookies()).toEqual([]);

  await context.close();
});
