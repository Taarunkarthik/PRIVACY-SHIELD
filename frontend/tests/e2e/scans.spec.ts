import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';

test('real worker scans synthetic rows and exposes sanitized sampled findings', async ({ page }, testInfo) => {
  test.setTimeout(300000);
  const passwordPath = process.env.PS_E2E_PASSWORD_FILE;
  if (!passwordPath) throw new Error('Set PS_E2E_PASSWORD_FILE to an existing account password file before running test:e2e.');
  const password = (await readFile(passwordPath, 'utf8')).replace(/[\r\n]+$/, '');
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.name));
  await page.goto('/scans');
  await page.getByLabel('Email address').fill(process.env.PS_E2E_ADMIN_EMAIL ?? 'admin@example.com');
  await page.getByLabel('Password', { exact: true }).fill(password).catch(() => { throw new Error('The login password field could not be filled.'); });
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Scan Results.' })).toBeVisible();
  await page.getByLabel('Database connection', { exact: true }).selectOption({ label: process.env.PS_E2E_CONNECTION_NAME ?? 'Synthetic enterprise' });
  await expect(page.getByRole('button', { name: 'Start scan', exact: true })).toBeEnabled();
  await page.getByLabel('Rows per table', { exact: false }).fill('10');
  const started = page.waitForResponse((response) => response.url().endsWith('/api/v1/scans') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Start scan', exact: true }).click();
  const response = await started;
  expect(response.status()).toBe(202);
  const created = await response.json() as { id: string; status: string };
  expect(['QUEUED', 'RUNNING']).toContain(created.status);
  await expect(page).toHaveURL(new RegExp(`job=${created.id}`));
  const selected = page.getByRole('region', { name: 'Selected scan status' });
  // Wait until the panel shows the scan just started. Until it re-renders it
  // still shows the previously selected scan, whose "Completed" status and
  // findings would otherwise be read in place of the new scan's.
  await expect(selected.getByRole('heading', { name: `Scan ${created.id.slice(0, 8)}` })).toBeVisible();
  await expect(selected.getByText('Completed', { exact: true })).toBeVisible({ timeout: 240000 });
  const findings = page.getByRole('region', { name: 'Sampled scan findings' });
  await expect(findings).toBeVisible();
  await expect(findings.getByRole('article').first()).toBeVisible();
  let hasPan = false;
  let hasAadhaar = false;
  let hasJsonPath = false;
  let hasFreeText = false;
  for (let resultPage = 1; resultPage <= 20; resultPage++) {
    const labels = await findings.locator('.category-chip').allTextContents();
    hasPan ||= labels.some((text) => text.includes('PAN candidate'));
    hasAadhaar ||= labels.some((text) => text.includes('Aadhaar candidate'));
    hasJsonPath ||= (await findings.locator('.finding-heading code').count()) > 0;
    hasFreeText ||= (await findings.getByRole('article', { name: 'Finding enterprise.support_records.body' }).count()) > 0;
    await expect(findings).not.toContainText('customer1@example.com');
    await expect(findings).not.toContainText('Please contact customer');
    await expect(findings).not.toContainText('ABCDE0001F');
    const next = findings.getByRole('button', { name: 'Next', exact: true });
    if (!(await next.count()) || !(await next.isEnabled())) break;
    await next.click();
    await expect(findings.getByText(`Page ${resultPage + 1} of`, { exact: false })).toBeVisible();
    await expect(findings.getByRole('article').first()).toBeVisible();
  }
  expect(hasPan).toBe(true);
  expect(hasAadhaar).toBe(true);
  expect(hasJsonPath).toBe(true);
  expect(hasFreeText).toBe(true);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: testInfo.outputPath('scans-desktop.png'), fullPage: true });
  await page.reload();
  await expect(selected.getByText('Completed', { exact: true })).toBeVisible();
  await expect(findings.getByRole('article').first()).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => window.scrollTo(0, 0));
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('scans-mobile.png'), fullPage: true });
  expect(pageErrors).toEqual([]);
});
