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
export type ParsedConnectionUrl = {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  sslMode?: Connection['ssl_mode'];
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
export type ConnectionSecurityFinding = {
  code: 'PUBLIC_TABLE_READ' | 'READER_SOURCE_ACCESS' | 'PUBLIC_SCHEMA_CREATE' | 'TABLE_WITHOUT_PRIMARY_KEY';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  title: string;
  description: string;
  schema_name: string;
  table_name: string | null;
};
export type ConnectionCheck = {
  status: 'ok';
  schemas: string[];
  table_count: number;
  security_findings: ConnectionSecurityFinding[];
};

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

/**
 * Reads a pasted `postgresql://` URL into the fields the form already submits.
 * Returns null for anything incomplete, so a half-typed URL never overwrites
 * fields the operator has already set.
 *
 * `prefer` and `allow` are not among the four modes this product offers, so they
 * take the closest one that still encrypts (`require`) or does not (`disable`).
 */
export function parseConnectionUrl(value: string): ParsedConnectionUrl | null {
  const text = value.trim();
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  if (url.protocol !== 'postgresql:' && url.protocol !== 'postgres:') return null;

  const host = url.hostname.replace(/^\[(.*)]$/, '$1');
  let database: string;
  let username: string;
  let password: string;
  try {
    database = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
    username = decodeURIComponent(url.username);
    password = decodeURIComponent(url.password);
  } catch {
    return null;
  }
  if (!host || !username || !database || database.includes('/')) return null;

  const port = url.port ? Number(url.port) : 5432;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;

  const ssl = (url.searchParams.get('sslmode') ?? '').toLowerCase();
  const sslMode = ssl === 'prefer' ? 'require'
    : ssl === 'allow' ? 'disable'
      : ssl === 'true' || ssl === '1' ? 'require'
        : ssl === 'false' || ssl === '0' ? 'disable'
          : ssl === 'disable' || ssl === 'require' || ssl === 'verify-ca' || ssl === 'verify-full' ? ssl
            : undefined;

  return { host, port, database, username, password, sslMode };
}
