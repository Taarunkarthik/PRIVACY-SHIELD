import { describe, expect, it } from 'vitest';
import { parseConnectionUrl } from '../src/api/connections';

describe('parseConnectionUrl', () => {
  it('reads a complete URL into the form fields', () => {
    expect(parseConnectionUrl('postgresql://ps_scanner:secret@target-db:5432/enterprise_demo?sslmode=disable')).toEqual({
      host: 'target-db',
      port: 5432,
      database: 'enterprise_demo',
      username: 'ps_scanner',
      password: 'secret',
      sslMode: 'disable',
    });
  });

  it('accepts the short scheme, a default port and a percent-encoded password', () => {
    expect(parseConnectionUrl('postgres://reader:p%40ss@db.example.test/reports')).toMatchObject({
      host: 'db.example.test',
      port: 5432,
      database: 'reports',
      username: 'reader',
      password: 'p@ss',
    });
  });

  it('strips IPv6 brackets and maps the TLS shorthands', () => {
    expect(parseConnectionUrl('postgresql://u:p@[::1]:6543/db?sslmode=prefer')).toMatchObject({
      host: '::1',
      port: 6543,
      sslMode: 'require',
    });
    expect(parseConnectionUrl('postgresql://u:p@host/db?sslmode=allow')?.sslMode).toBe('disable');
    expect(parseConnectionUrl('postgresql://u:p@host/db?sslmode=verify-full')?.sslMode).toBe('verify-full');
    expect(parseConnectionUrl('postgresql://u:p@host/db')?.sslMode).toBeUndefined();
  });

  it('returns null rather than filling fields from an incomplete URL', () => {
    for (const value of [
      '',
      'not a url',
      'mysql://u:p@host/db',
      'postgresql://host/db',
      'postgresql://u:p@host/',
      'postgresql://u:p@host:99999/db',
      'postgresql://u:p@host/a/b',
    ]) {
      expect(parseConnectionUrl(value)).toBeNull();
    }
  });
});
