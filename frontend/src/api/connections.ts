import { ApiError } from './client';

export type Connection = {
  id: string;
  name: string;
  host: string;
  port: number;
  database_name: string;
  ssl_mode: 'disable' | 'require' | 'verify-ca' | 'verify-full';
  scanner_username: string;
  deployer_username: string | null;
  is_active: boolean;
  created_at: string;
};

export type ConnectionPage = { items: Connection[]; total: number; page: number; page_size: number };
export type ConnectionInput = Pick<Connection, 'name' | 'host' | 'port' | 'database_name' | 'ssl_mode' | 'scanner_username'> & {
  scanner_password?: string;
  deployer_username?: string;
  deployer_password?: string;
  is_active?: boolean;
};
export type SchemaColumn = { name: string; data_type: string; udt_name: string; nullable: boolean; ordinal: number; is_primary_key: boolean; is_jsonb: boolean };
export type ForeignKey = { name: string; columns: string[]; referenced_schema: string; referenced_table: string; referenced_columns: string[] };
export type SchemaTable = {
  schema: string;
  name: string;
  oid: number;
  row_estimate: number;
  rls_enabled: boolean;
  columns: SchemaColumn[];
  primary_key: string[];
  foreign_keys: ForeignKey[];
};
export type SchemaSnapshot = { snapshot_id: string; discovered_at: string; fingerprint: string; catalog: { schemas: string[]; tables: SchemaTable[] } };
export type ConnectionCheck = { status: 'ok'; schemas: string[]; table_count: number };

/**
 * The connection a page opens on when its address names none: the active one
 * that has been registered longest, so a workspace keeps opening on the database
 * its existing scans and policies belong to when another database is added.
 */
export function defaultConnectionId(connections: Connection[]): string {
  const oldestFirst = [...connections].sort((a, b) => (Date.parse(a.created_at) - Date.parse(b.created_at)) || 0);
  return (oldestFirst.find((item) => item.is_active) ?? oldestFirst[0])?.id ?? '';
}

export function discoveryScope(value: string): { schemas?: string[] } {
  const names = [...new Set(value.split(',').map((name) => name.trim()).filter(Boolean))];
  return names.length ? { schemas: names } : {};
}

export function connectionError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 409) return 'A connection with this name already exists. Choose a different name.';
    if (error.status === 422) return 'Check the connection details and schema names, then try again.';
    if (error.status === 502) return 'The database could not be accessed. Check its address, credentials, and schema permissions.';
    if (error.status === 404) return 'This connection is no longer available. Refresh the connection list.';
    return error.message;
  }
  return 'This request could not be completed. Please try again.';
}
