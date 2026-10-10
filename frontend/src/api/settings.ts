import { api } from './client';

export interface DetectionPattern {
  id: string;
  name: string;
  category: string;
  regex: string;
  enabled: boolean;
}

export interface WorkspaceSettings {
  workspace_name: string;
  retention_days: number;
  custom_patterns: DetectionPattern[];
}

export type SettingsPatch = Partial<Pick<WorkspaceSettings, 'workspace_name' | 'retention_days' | 'custom_patterns'>>;

// Client-side mirrors of the server bounds so users get feedback before a request.
export const PATTERN_LIMIT = 20;
export const PATTERN_NAME_LIMIT = 60;
export const PATTERN_REGEX_LIMIT = 200;
export const WORKSPACE_NAME_LIMIT = 80;
export const MIN_RETENTION_DAYS = 1;
export const MAX_RETENTION_DAYS = 3650;

// Categories accepted by the local PII detector. Custom patterns reuse the same vocabulary.
export const patternCategories = [
  'EMAIL_ADDRESS',
  'PHONE_NUMBER',
  'PERSON',
  'LOCATION',
  'CREDIT_CARD',
  'IBAN_CODE',
  'PAN_CANDIDATE',
  'AADHAAR_CANDIDATE',
  'BANK_ACCOUNT',
] as const;

export type PatternCategory = typeof patternCategories[number];

const categoryLabels: Record<string, string> = {
  EMAIL_ADDRESS: 'Email address',
  PHONE_NUMBER: 'Phone number',
  PERSON: 'Person name',
  LOCATION: 'Location',
  CREDIT_CARD: 'Credit card',
  IBAN_CODE: 'IBAN',
  PAN_CANDIDATE: 'PAN candidate',
  AADHAAR_CANDIDATE: 'Aadhaar candidate',
  BANK_ACCOUNT: 'Bank account',
};

export function patternCategoryLabel(value: string) {
  return categoryLabels[value] ?? value;
}

export function getSettings(signal?: AbortSignal) {
  return api<WorkspaceSettings>('/settings', { signal });
}

export function updateSettings(patch: SettingsPatch, csrfToken: string) {
  return api<WorkspaceSettings>('/settings', { method: 'PATCH', csrfToken, body: JSON.stringify(patch) });
}
