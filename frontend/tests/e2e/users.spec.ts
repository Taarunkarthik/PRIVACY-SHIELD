import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';

test('an administrator adds an analyst, who signs in with fewer rights and is then deactivated', async ({ page }) => {
  const adminEmail = process.env.PS_E2E_ADMIN_EMAIL ?? 'admin@example.com';
  const passwordPath = process.env.PS_E2E_PASSWORD_FILE;
  if (!passwordPath) throw new Error('Set PS_E2E_PASSWORD_FILE to an existing account password file before running test:e2e.');
  const adminPassword = (await readFile(passwordPath, 'utf8')).replace(/[\r\n]+$/, '');
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.name));
  // A new address each run, so the spec can be repeated against the same database.
  const analystEmail = `e2e-analyst-${Date.now()}@example.com`;
  const analystPassword = `e2e-${Date.now()}-analyst-pass`;

  async function signIn(email: string, password: string) {
    await page.goto('/');
    await page.getByLabel('Email address').fill(email);
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Workspace overview.' })).toBeVisible();
  }
  async function signOut() {
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page.getByRole('heading', { name: 'Sign in to PrivacyShield' })).toBeVisible();
  }

  await signIn(adminEmail, adminPassword);
  const nav = page.getByRole('navigation', { name: 'Main navigation' });
  await nav.getByRole('link', { name: 'Users', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Users.' })).toBeVisible();
  const own = page.getByRole('row', { name: new RegExp(adminEmail.replace(/[.+]/g, '\\$&')) });
  await expect(own.getByRole('button', { name: /Change role/ })).toHaveCount(0);
  await expect(own.getByRole('button', { name: /Deactivate/ })).toHaveCount(0);

  await page.getByRole('button', { name: 'Add user' }).click();
  const dialog = page.getByRole('dialog', { name: 'Add user' });
  await dialog.getByLabel('Email address').fill(analystEmail);
  await dialog.getByLabel('Role').selectOption('ANALYST');
  await dialog.getByLabel('Password', { exact: true }).fill(analystPassword);
  await dialog.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByRole('status')).toContainText(`${analystEmail} was added as analyst`);
  await expect(page.getByText(analystPassword)).toHaveCount(0);
  await expect(page.getByRole('row', { name: new RegExp(analystEmail.replace(/[.+]/g, '\\$&')) })).toBeVisible();
  await signOut();

  // The analyst sees the workspace, but not account management or approval.
  await signIn(analystEmail, analystPassword);
  await expect(nav.getByRole('link')).toHaveCount(9);
  await expect(nav.getByRole('link', { name: 'Users', exact: true })).toHaveCount(0);
  await page.goto('/users');
  await expect(page.getByText('Accounts are managed by administrators')).toBeVisible();
  await signOut();

  // Deactivating the account takes effect at once.
  await signIn(adminEmail, adminPassword);
  await nav.getByRole('link', { name: 'Users', exact: true }).click();
  await page.getByRole('button', { name: `Deactivate ${analystEmail}` }).click();
  await expect(page.getByRole('status')).toContainText('was deactivated and signed out');
  await expect(page.getByRole('button', { name: `Reactivate ${analystEmail}` })).toBeVisible();
  // The change is in the audit log.
  await nav.getByRole('link', { name: 'Audit Logs', exact: true }).click();
  const timeline = page.getByRole('region', { name: 'Audit events' });
  await expect(timeline.getByText('USER DEACTIVATED').first()).toBeVisible();
  await expect(timeline.getByText('USER CREATED AS ANALYST').first()).toBeVisible();
  expect(pageErrors).toEqual([]);
});
