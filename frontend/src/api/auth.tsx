import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { api, ApiError, SESSION_EXPIRED } from './client';
import type { User } from './client';

type AuthContextValue = {
  user: User | null;
  loading: boolean;
  error: string;
  expired: boolean;
  refresh: () => void;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expired, setExpired] = useState(false);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError('');
    api<User>('/auth/me', { signal: controller.signal })
      .then(setUser)
      .catch((reason: unknown) => {
        if (controller.signal.aborted) return;
        setUser(null);
        // A first visit without a cookie is expected, not a session-expiry warning.
        if (reason instanceof ApiError && reason.status === 401) setExpired(false);
        else setError(reason instanceof Error ? reason.message : 'Unable to restore your session.');
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [revision]);

  useEffect(() => {
    const expire = () => { setUser(null); setExpired(true); };
    window.addEventListener(SESSION_EXPIRED, expire);
    return () => window.removeEventListener(SESSION_EXPIRED, expire);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const result = await api<User>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
    setUser(result);
    setExpired(false);
    setError('');
  }, []);

  const logout = useCallback(async () => {
    if (!user) return;
    try {
      await api<void>('/auth/logout', { method: 'POST', csrfToken: user.csrf_token });
      setUser(null);
      setExpired(false);
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) return;
      throw reason;
    }
  }, [user]);

  return <AuthContext.Provider value={{ user, loading, error, expired, refresh: () => setRevision((value) => value + 1), login, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth requires AuthProvider');
  return context;
}
