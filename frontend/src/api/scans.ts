import { ApiError } from './client';

export type ScanStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
export type ScanJob = {
  id: string; connection_id: string; snapshot_id: string; status: ScanStatus;
  sample_limit: number; progress: number; created_at: string;
  started_at: string | null; finished_at: string | null; error_code: string | null;
};
export type ScanPage = { items: ScanJob[]; total: number; page: number; page_size: number };
export type ScanCoverage = {
  mode: 'bounded_sample'; sample_limit: number; max_cell_chars: number; max_cell_bytes: number;
  values_truncated: number; values_skipped: number; json_truncated: number; path_limit_reached: number; unsupported_type: boolean;
};
export type ScanResult = {
  id: string; scan_job_id: string; schema_name: string; table_name: string; column_name: string; json_path: string;
  sampled_rows: number; matching_rows: number; confidence: number; category_counts: Record<string, number>;
  sanitized_evidence: { labels: string[]; coverage: ScanCoverage }; created_at: string;
};
export type ResultPage = { items: ScanResult[]; total: number; page: number; page_size: number };

export const activeScan = (job: ScanJob) => job.status === 'QUEUED' || job.status === 'RUNNING';
export const activeScanPage = (page: ScanPage) => page.items.some(activeScan);
export const statusLabel: Record<ScanStatus, string> = { QUEUED: 'Queued', RUNNING: 'Running', COMPLETED: 'Completed', FAILED: 'Failed', CANCELLED: 'Cancelled' };

const categories: Record<string, string> = {
  EMAIL_ADDRESS: 'Email address', PHONE_NUMBER: 'Phone number', PERSON: 'Person name', LOCATION: 'Location',
  CREDIT_CARD: 'Credit card', IBAN_CODE: 'IBAN', PAN_CANDIDATE: 'PAN candidate',
  AADHAAR_CANDIDATE: 'Aadhaar candidate', BANK_ACCOUNT: 'Bank-account candidate',
};
export function categoryLabel(value: string) { return categories[value] ?? 'Other candidate'; }

export function scanError(reason: unknown) {
  if (reason instanceof ApiError) {
    if (reason.status === 409) return 'The connection or schema is no longer ready for this scan. Refresh its schema before trying again.';
    if (reason.status === 422) return 'Check the selected connection, saved schema, and sample limit.';
    if (reason.status === 503) return 'The scan could not be queued. Please try again when the scanning service is available.';
    return reason.message;
  }
  return 'The scan request could not be completed. Please try again.';
}

export function failureMessage(code: string | null) {
  const messages: Record<string, string> = {
    SCHEMA_DRIFT: 'The database schema changed after discovery. Discover it again before starting a new scan.',
    CONNECTION_INACTIVE: 'This connection was deactivated. An administrator can reactivate it before a new scan.',
    CONNECTION_CHANGED: 'The connection settings changed after this scan was created. Discover its schema again before starting a new scan.',
    TARGET_UNAVAILABLE: 'The database could not be reached. Check the connection before starting a new scan.',
    SOURCE_ACCESS_DENIED: 'The scanner could not read the selected source. Check its read permissions.',
    RESULT_LIMIT_EXCEEDED: 'This scan exceeded its result limit. Discover fewer schemas and try again.',
    SCAN_TIMEOUT: 'The scan reached its time limit. Try a smaller sample or fewer tables.',
    ATTEMPT_LIMIT_EXCEEDED: 'The scan could not finish after recovery attempts. Start a new scan when the services are ready.',
  };
  return (code && messages[code]) || 'The scan did not finish. Check the connection and start a new scan.';
}

export function coverageLimits(coverage: ScanCoverage | undefined): string[] {
  if (!coverage) return ['Coverage information is unavailable.'];
  const limits: string[] = [];
  if (coverage.unsupported_type) limits.push('This column type was not assessed.');
  if (coverage.values_truncated) limits.push(`${coverage.values_truncated.toLocaleString()} values truncated`);
  if (coverage.values_skipped) limits.push(`${coverage.values_skipped.toLocaleString()} values skipped`);
  if (coverage.json_truncated) limits.push(`${coverage.json_truncated.toLocaleString()} JSON values bounded or truncated`);
  if (coverage.path_limit_reached) limits.push(`${coverage.path_limit_reached.toLocaleString()} JSON path limits reached`);
  return limits;
}
