import { ApiError } from './client';
import { categoryLabel } from './scans';

export type ClassificationStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'PARTIAL' | 'FAILED';
export type ClassificationJob = {
  id: string; scan_id: string; status: ClassificationStatus; progress: number;
  total_results: number; completed_results: number; failed_results: number;
  model: string; prompt_version: string; error_code: string | null;
  created_at: string; started_at: string | null; finished_at: string | null;
};
export type ClassificationJobPage = { items: ClassificationJob[]; total: number; page: number; page_size: number };
export type Risk = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Recommendation = 'KEEP' | 'REDACT' | 'PARTIAL' | 'PSEUDONYMIZE' | 'NULLIFY' | 'RESTRICT';
export type Classification = {
  id: string; job_id: string; scan_result_id: string; scan_id: string;
  schema_name: string; table_name: string; column_name: string; json_path: string;
  category: string; risk: Risk; recommendation: Recommendation; confidence: number;
  reason: string; model: string; prompt_version: string; requires_approval: true; created_at: string;
};
export type ClassificationPage = { items: Classification[]; total: number; page: number; page_size: number };

export const activeClassification = (job: ClassificationJob) => job.status === 'QUEUED' || job.status === 'RUNNING';
export const activeClassificationPage = (page: ClassificationJobPage) => page.items.some(activeClassification);
export const classificationStatus: Record<ClassificationStatus, string> = { QUEUED: 'Queued', RUNNING: 'Running', COMPLETED: 'Completed', PARTIAL: 'Partial', FAILED: 'Failed' };
export const riskLabels: Record<Risk, string> = { LOW: 'Low', MEDIUM: 'Medium', HIGH: 'High', CRITICAL: 'Critical' };
export const recommendationLabels: Record<Recommendation, string> = { KEEP: 'Keep unchanged', REDACT: 'Redact', PARTIAL: 'Partially mask', PSEUDONYMIZE: 'Pseudonymize', NULLIFY: 'Replace with null', RESTRICT: 'Restrict access' };
export function classificationCategory(value: string) {
  const extra: Record<string, string> = { NONE: 'No category identified', PERSONAL_IDENTIFIER: 'Personal identifier', SENSITIVE_TEXT: 'Sensitive text', DATE_OF_BIRTH: 'Date of birth', CUSTOM_SENSITIVE: 'Other sensitive data' };
  return extra[value] ?? categoryLabel(value);
}
export function classificationError(reason: unknown) {
  if (reason instanceof ApiError) {
    if (reason.status === 409) return 'Choose a completed scan with available findings. Another classification may already be active for this scan.';
    if (reason.status === 422) return 'Choose between 1 and 50 findings from this completed scan.';
    if (reason.status === 503) return 'AI classification is unavailable. Your scan findings remain available for manual review.';
    return reason.message;
  }
  return 'AI classification could not be completed. Your scan findings remain available for manual review.';
}
export function classificationFailure(code: string | null) {
  const messages: Record<string, string> = {
    AI_UNAVAILABLE: 'The AI service or model is unavailable.',
    AI_TIMEOUT: 'The AI service did not respond within its time limit.',
    OLLAMA_UNAVAILABLE: 'The AI service or model is unavailable.',
    OLLAMA_TIMEOUT: 'The AI service did not respond within its time limit.',
    OLLAMA_HTTP_ERROR: 'The AI service could not complete the request.',
    AI_INVALID_RESPONSE: 'The AI response did not pass validation and was not accepted.',
    AI_RESPONSE_TOO_LARGE: 'The AI response exceeded the accepted size and was not used.',
    AI_INPUT_INVALID: 'The saved evidence could not be used for this classification.',
    AI_INPUT_TOO_LARGE: 'The saved evidence exceeded the classification input limit.',
    AI_MODEL_MISMATCH: 'The response came from an unexpected AI model and was not accepted.',
    CLASSIFICATION_TIMEOUT: 'Classification reached its time limit. Try fewer findings in a new request.',
    RESULT_METADATA_MISMATCH: 'The saved findings no longer match the classification request.',
    SCAN_NOT_COMPLETED: 'Classification requires a completed scan.',
    PROMPT_VERSION_CHANGED: 'The classification instructions changed. Start a new classification request.',
    ATTEMPT_LIMIT_EXCEEDED: 'This job could not finish after recovery attempts.',
  };
  return (code && messages[code]) || 'Some recommendations could not be generated or validated.';
}
