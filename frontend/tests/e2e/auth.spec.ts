import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';

test('real browser signs in, renders live totals, navigates, and signs out', async ({ page, context }, testInfo) => {
  const email = process.env.PS_E2E_ADMIN_EMAIL ?? 'admin@example.com';
  const passwordPath = process.env.PS_E2E_PASSWORD_FILE;
  if (!passwordPath) throw new Error('Set PS_E2E_PASSWORD_FILE to an existing account password file before running test:e2e.');
  const password = (await readFile(passwordPath, 'utf8')).replace(/[\r\n]+$/, '');
  if (!password) throw new Error('E2E password file must contain an existing account password.');
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.name));

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Sign in to PrivacyShield' })).toBeVisible();
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password).catch(() => {
    throw new Error('The login password field could not be filled.');
  });
  const summaryResponse = page.waitForResponse((response) => response.url().endsWith('/api/v1/dashboard/summary') && response.status() === 200);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  const summary = await (await summaryResponse).json() as Record<string, number>;
  await expect(page.getByRole('heading', { name: 'Workspace overview.' })).toBeVisible();
  for (const [label, key] of [
    ['Connected databases', 'databases'],
    ['Discovered tables', 'tables'],
    ['Sensitive columns', 'sensitive_columns'],
    ['Deployed policies', 'deployed_policies'],
  ]) {
    expect(Number.isSafeInteger(summary[key])).toBe(true);
    expect(summary[key]).toBeGreaterThanOrEqual(0);
    await expect(page.locator('.stat-card').filter({ hasText: label }).locator('.stat-number')).toHaveText(summary[key].toLocaleString());
  }
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  const sessionCookie = (await context.cookies()).find((cookie) => cookie.name === 'ps_session');
  expect(Boolean(sessionCookie)).toBe(true);
  expect(sessionCookie?.httpOnly).toBe(true);
  expect(sessionCookie?.sameSite).toBe('Lax');
  await expect(page.getByLabel('Password', { exact: true })).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath('dashboard-desktop.png'), fullPage: true });

  await page.reload();
  await expect(page.getByRole('heading', { name: 'Workspace overview.' })).toBeVisible();
  const nav = page.getByRole('navigation', { name: 'Main navigation' });
  await expect(nav.getByRole('link')).toHaveCount(9);
  for (const label of ['Connections', 'Schema Explorer', 'Scan Results', 'AI Classification', 'Masking Policies', 'Approval Queue', 'Audit Logs', 'Settings']) {
    await nav.getByRole('link', { name: label, exact: true }).click();
    await expect(page.getByRole('heading', { name: new RegExp(`^${label}\\.?$`) })).toBeVisible();
  }
  await nav.getByRole('link', { name: 'Overview', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Workspace overview.' })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(nav).not.toBeVisible();
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('dashboard-mobile.png'), fullPage: true });
  await page.getByRole('button', { name: 'Open navigation' }).click();
  await expect(nav).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(nav).not.toBeVisible();
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeFocused();
  await page.getByRole('button', { name: 'Open navigation' }).click();
  await nav.getByRole('link', { name: 'Settings', exact: true }).click();
  await expect(nav).not.toBeVisible();
  await expect(page.getByRole('heading', { name: /^Settings\.?$/ })).toBeVisible();
  await page.getByRole('button', { name: 'Open navigation' }).click();
  const logoutResponse = page.waitForResponse((response) => response.url().endsWith('/api/v1/auth/logout') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  expect((await logoutResponse).status()).toBe(204);
  await expect(page.getByRole('heading', { name: 'Sign in to PrivacyShield' })).toBeVisible();
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');
  await page.screenshot({ path: testInfo.outputPath('signed-out-mobile.png'), fullPage: true });
  expect((await context.request.get('/api/v1/auth/me')).status()).toBe(401);
  expect(pageErrors).toEqual([]);
});
