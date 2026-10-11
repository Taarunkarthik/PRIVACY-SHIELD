export type PolicyAction = 'KEEP' | 'REDACT' | 'PARTIAL' | 'MASK_EMAIL' | 'MASK_PHONE' | 'MASK_ID' | 'PSEUDONYMIZE' | 'NULLIFY' | 'RESTRICT';
export type PolicyStatus = 'DRAFT' | 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'DEPLOYED' | 'FAILED';
export type DeploymentStatus = 'QUEUED' | 'RUNNING' | 'RECONCILING' | 'COMPLETED' | 'FAILED';

export interface PolicyRule {
  policy_id: string;
  column_name: string;
  action: PolicyAction;
  pseudonym_domain: string | null;
  classification_id: string | null;
}

export interface Policy {
  id: string;
  connection_id: string;
  schema_name: string;
  table_name: string;
  version: number;
  status: PolicyStatus;
  schema_fingerprint: string;
  compiled_plan_fingerprint: string | null;
  created_by: string;
  created_at: string;
  rules: PolicyRule[];
}

export interface PolicyPage { items: Policy[]; total: number; page: number; page_size: number }

export interface PolicyPreviewColumn {
  name: string;
  data_type: string;
  action: PolicyAction;
  pseudonym_domain: string | null;
  source_column: string;
}

export interface PolicyPreview {
  policy_id: string;
  schema_name: string;
  table_name: string;
  view_schema: string;
  view_name: string;
  columns: PolicyPreviewColumn[];
  sql: string;
}

export interface SampleColumn { name: string; data_type: string; action: PolicyAction }

/** Compiled expressions applied to fabricated inputs. No source rows are read. */
export interface PolicySamples {
  policy_id: string;
  status: 'OK' | 'UNAVAILABLE';
  source: 'FABRICATED';
  columns: SampleColumn[];
  before: (string | null)[][];
  after: (string | null)[][];
}

/** Rows read through the deployed view, with what the reader role can access. */
export interface ProtectedOutput {
  policy_id: string;
  view_schema: string;
  view_name: string;
  source_schema: string;
  source_table: string;
  columns: SampleColumn[];
  rows: (string | null)[][];
  row_limit: number;
  access: { reader_role: string; reader_can_read_view: boolean; reader_can_read_source: boolean };
}

export interface RuleSuggestion {
  column_name: string;
  data_type: string;
  source: 'DETECTOR' | 'AI' | 'NO_FINDINGS' | 'NOT_SCANNED';
  action: PolicyAction | null;
  category: string | null;
  confidence: number | null;
  sampled_rows: number;
  matching_rows: number;
  classification_id: string | null;
  ai_recommendation: string | null;
  ai_risk: string | null;
}

export interface PolicySuggestions {
  connection_id: string;
  schema_name: string;
  table_name: string;
  scan_id: string | null;
  scanned_at: string | null;
  columns: RuleSuggestion[];
}

export interface Deployment {
  id: string;
  policy_id: string;
  requested_by: string;
  idempotency_key: string;
  status: DeploymentStatus;
  target_receipt: Record<string, unknown> | null;
  finished_at: string | null;
  error_code: string | null;
  created_at: string;
}

export interface DeploymentPage { items: Deployment[]; total: number; page: number; page_size: number }

export interface AuditEvent {
  id: string;
  actor_id: string | null;
  event_type: string;
  subject_type: string;
  subject_id: string | null;
  correlation_id: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface AuditEventPage { items: AuditEvent[]; total: number; page: number; page_size: number }

export const policyStatusLabel: Record<PolicyStatus, string> = {
  DRAFT: 'Draft',
  PENDING_APPROVAL: 'Pending approval',
  APPROVED: 'Approved',
  REJECTED: 'Rejected',
  DEPLOYED: 'Deployed',
  FAILED: 'Failed',
};

export const deploymentStatusLabel: Record<DeploymentStatus, string> = {
  QUEUED: 'Queued',
  RUNNING: 'Running',
  RECONCILING: 'Reconciling',
  COMPLETED: 'Completed',
  FAILED: 'Failed',
};

export const actionLabel: Record<PolicyAction, string> = {
  KEEP: 'Keep',
  REDACT: 'Redact',
  PARTIAL: 'Partial mask',
  MASK_EMAIL: 'Mask email',
  MASK_PHONE: 'Mask phone',
  MASK_ID: 'Mask ID number',
  PSEUDONYMIZE: 'Pseudonymize',
  NULLIFY: 'Nullify',
  RESTRICT: 'Restrict',
};

/** What each action does to a value, shown where a rule is chosen. */
export const actionHint: Record<PolicyAction, string> = {
  KEEP: 'Shown unchanged',
  REDACT: 'Replaced with [REDACTED]',
  PARTIAL: 'Last four characters kept',
  MASK_EMAIL: 'First letter and domain kept: p***@example.com',
  MASK_PHONE: 'Last four digits kept: +** ***** *3210',
  MASK_ID: 'Last four characters kept, format preserved: **** **** 0124',
  PSEUDONYMIZE: 'Replaced with a stable keyed token',
  NULLIFY: 'Returned as NULL',
  RESTRICT: 'Returned as NULL',
};
