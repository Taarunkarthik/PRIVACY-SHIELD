export type PolicyAction = 'KEEP' | 'REDACT' | 'PARTIAL' | 'MASK_EMAIL' | 'MASK_PHONE' | 'MASK_ID' | 'PSEUDONYMIZE' | 'NULLIFY' | 'RESTRICT';
export type PolicyStatus = 'DRAFT' | 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'DEPLOYED' | 'FAILED';
export type DeploymentStatus = 'QUEUED' | 'RUNNING' | 'RECONCILING' | 'COMPLETED' | 'FAILED';

/** Who a rule is for. Each audience reads its own masked view through its own database role. */
export type Audience = 'reader' | 'support' | 'analyst';
export const AUDIENCES: Audience[] = ['reader', 'support', 'analyst'];

export interface PolicyRule {
  policy_id: string;
  column_name: string;
  audience: Audience;
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
  audience: Audience;
  /** The database role that reads this audience's view. */
  role: string;
  /** Every audience this policy creates a view for. */
  audiences: Audience[];
}

export interface SampleColumn { name: string; data_type: string; action: PolicyAction }

/** Compiled expressions applied to fabricated inputs. No source rows are read. */
export interface PolicySamples {
  policy_id: string;
  status: 'OK' | 'UNAVAILABLE';
  source: 'FABRICATED';
  audience: Audience;
  columns: SampleColumn[];
  before: (string | null)[][];
  after: (string | null)[][];
}

/**
 * Rows read through one audience's deployed view, with what that audience's role
 * can access. `access.reader_role` names the role of the audience asked for.
 */
export interface ProtectedOutput {
  policy_id: string;
  audience: Audience;
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

export const audienceLabel: Record<Audience, string> = {
  reader: 'General readers',
  support: 'Support',
  analyst: 'Analysts',
};

/** The target database role each audience reads through. */
export const audienceRole: Record<Audience, string> = {
  reader: 'ps_reader',
  support: 'ps_support',
  analyst: 'ps_analyst',
};

/** The audiences a policy creates a view for: general readers always, the others once they have a rule. */
export function policyAudiences(policy: Pick<Policy, 'rules'>): Audience[] {
  return AUDIENCES.filter((audience) => audience === 'reader' || policy.rules.some((rule) => (rule.audience ?? 'reader') === audience));
}

/** What to do about a failed deployment, for the codes a person can act on. */
export const deploymentErrorHint: Record<string, string> = {
  AUDIENCE_ROLE_MISSING: 'The target database has no role for one of this policy\'s audiences. Create ps_support and ps_analyst (see the masking audiences guide), then deploy again.',
  AUDIENCE_VIEW_IN_USE: 'Another database object depends on a view this version removes. Drop that object, then deploy again.',
  ACCESS_VERIFICATION_FAILED: 'A role could read more than the policy allows, so nothing was changed. Check role memberships and grants in the target database.',
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
