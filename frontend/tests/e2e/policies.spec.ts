import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';

// Human-readable statuses rendered by the Masking Policies page.
const policyStatusNames = ['Draft', 'Pending approval', 'Approved', 'Rejected', 'Deployed', 'Failed'];

test('real browser reviews masking policies, previews a policy, and opens approvals and deployments', async ({ page }, testInfo) => {
  const passwordPath = process.env.PS_E2E_PASSWORD_FILE;
  if (!passwordPath) throw new Error('Set PS_E2E_PASSWORD_FILE to an existing account password file before running test:e2e.');
  const password = (await readFile(passwordPath, 'utf8')).replace(/[\r\n]+$/, '');
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.name));

  await page.goto('/policies');
  await page.getByLabel('Email address').fill(process.env.PS_E2E_ADMIN_EMAIL ?? 'admin@example.com');
  await page.getByLabel('Password', { exact: true }).fill(password).catch(() => {
    throw new Error('The login password field could not be filled.');
  });
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();

  await expect(page.getByRole('heading', { name: 'Masking Policies.' })).toBeVisible();
  const policiesRegion = page.getByRole('region', { name: 'Policies' });
  const policyRows = policiesRegion.locator('button.policy-row');
  // Either an existing policy list or the documented empty states must appear.
  const emptyState = page
    .getByRole('heading', { name: 'No policies yet' })
    .or(page.getByRole('heading', { name: 'No connections available' }));
  await expect(policyRows.first().or(emptyState)).toBeVisible();

  if ((await policyRows.count()) > 0) {
    // Status badges must resolve to one of the known human-readable labels.
    const statusPill = policiesRegion.locator('.policy-status').first();
    await expect(statusPill).toBeVisible();
    expect(policyStatusNames).toContain((await statusPill.innerText()).trim());

    await policyRows.first().click();
    const detail = page.getByRole('region', { name: 'Selected policy' });
    await expect(detail).toBeVisible();

    const previewResponse = page.waitForResponse(
      (response) => response.url().includes('/preview') && response.request().method() === 'GET',
    );
    await detail.getByRole('button', { name: 'Preview', exact: true }).click();
    expect((await previewResponse).ok()).toBe(true);

    const preview = page.getByRole('region', { name: 'Policy preview' });
    await expect(preview).toBeVisible();
    await expect(preview.getByRole('heading', { name: /^Preview: privacyshield_masked\./ })).toBeVisible();
    await expect(preview.locator('.preview-column').first()).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath('policies-desktop.png'), fullPage: true });
  } else {
    await expect(emptyState).toBeVisible();
  }

  // The Deployments history is reachable from the Policies page.
  await page.getByRole('link', { name: 'Deployments', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Deployments.' })).toBeVisible();
  const deploymentsRegion = page.getByRole('region', { name: 'Deployments' });
  await expect(deploymentsRegion).toBeVisible();
  await expect(deploymentsRegion.getByRole('heading', { name: /Deployment history/ })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('deployments-desktop.png'), fullPage: true });

  // The Approval Queue is a primary navigation destination.
  const nav = page.getByRole('navigation', { name: 'Main navigation' });
  await nav.getByRole('link', { name: 'Approval Queue', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Approval Queue.' })).toBeVisible();
  const approvalsRegion = page.getByRole('region', { name: 'Pending approvals' });
  await expect(approvalsRegion).toBeVisible();
  await expect(approvalsRegion.getByRole('heading', { name: /Pending approval/ })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('approvals-desktop.png'), fullPage: true });

  expect(pageErrors).toEqual([]);
});
