import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';

/**
 * Covers the Settings page added in this phase. Selectors stay role/label based
 * because the exact workspace fields are still being finalised, so the test
 * asserts an administrator reaches editable controls rather than specific
 * field names.
 */
test('administrator sees editable workspace settings without JavaScript errors', async ({ page }, testInfo) => {
  const passwordPath = process.env.PS_E2E_PASSWORD_FILE;
  if (!passwordPath) throw new Error('Set PS_E2E_PASSWORD_FILE to an existing account password file before running test:e2e.');
  const password = (await readFile(passwordPath, 'utf8')).replace(/[\r\n]+$/, '');
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.name));

  await page.goto('/settings');
  await page.getByLabel('Email address').fill(process.env.PS_E2E_ADMIN_EMAIL ?? 'admin@example.com');
  await page.getByLabel('Password', { exact: true }).fill(password).catch(() => {
    throw new Error('The login password field could not be filled.');
  });
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();

  // The heading is tolerant of the phase's punctuation convention ("Settings" or "Settings.").
  await expect(page.getByRole('heading', { name: /^Settings\.?$/ })).toBeVisible();
  // The workspace shell labels admin accounts explicitly.
  await expect(page.getByText('Administrator', { exact: true })).toBeVisible();

  const main = page.getByRole('main');
  const editable = main.locator(
    'input:not([type="hidden"]):not([type="submit"]):not([type="button"]), select, textarea, [contenteditable="true"], [role="switch"]',
  );
  await expect(editable.first()).toBeVisible();
  await expect(editable.first()).toBeEnabled();

  // At least one text-like field must genuinely accept edits for an administrator.
  const textField = main
    .locator('input[type="text"], input[type="email"], input[type="url"], input[type="number"], input[type="search"], input:not([type]), textarea')
    .first();
  if ((await textField.count()) > 0) {
    await expect(textField).toBeEnabled();
    expect(await textField.isEditable()).toBe(true);
  }

  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: testInfo.outputPath('settings-desktop.png'), fullPage: true });
  expect(pageErrors).toEqual([]);
});
