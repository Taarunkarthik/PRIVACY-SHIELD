export type AuditChainReason = 'HASH_MISMATCH' | 'LINK_MISMATCH' | 'INDEX_GAP' | 'MISSING_EVENT';

export interface AuditChainVerification {
  status: 'INTACT' | 'BROKEN';
  sealed: number;
  pending: number;
  head_index: number;
  head_hash: string | null;
  broken_index: number | null;
  reason: AuditChainReason | null;
  anchor_status: 'MATCH' | 'MISMATCH' | 'NOT_FOUND' | null;
  verified_at: string;
}

export const auditChainReasonText: Record<AuditChainReason, string> = {
  HASH_MISMATCH: 'The audit event at this position, or the hash recorded for it, was changed after the event was sealed.',
  LINK_MISMATCH: 'This entry no longer follows from the one before it. An entry at or just before this position was rewritten.',
  INDEX_GAP: 'The entry at this position is missing. An entry was removed from the chain.',
  MISSING_EVENT: 'The audit event that was sealed at this position no longer exists.',
};

export function shortHash(hash: string) {
  return hash.length > 20 ? `${hash.slice(0, 12)}…${hash.slice(-8)}` : hash;
}
