export type PolicyAction = 'KEEP' | 'REDACT' | 'PARTIAL' | 'PSEUDONYMIZE' | 'NULLIFY' | 'RESTRICT';
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
  PSEUDONYMIZE: 'Pseudonymize',
  NULLIFY: 'Nullify',
  RESTRICT: 'Restrict',
};
