import { useEffect, useState } from 'react';
import { api } from './client';
import { scanError } from './scans';

type Resource<T> = { url: string | null; data: T | null; loading: boolean; error: string };
const neverPoll = () => false;

// Poll only after successful active responses; errors and unmount cancel the timer and request.
export function usePollingResource<T>(url: string | null, revision = 0, shouldPoll: (data: T) => boolean = neverPoll) {
  const [state, setState] = useState<Resource<T>>({ url: null, data: null, loading: false, error: '' });
  useEffect(() => {
    if (!url) { setState({ url: null, data: null, loading: false, error: '' }); return; }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    setState((previous) => ({ url, data: previous.url === url ? previous.data : null, loading: true, error: '' }));
    async function fetchResource() {
      try {
        const data = await api<T>(url!, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setState({ url, data, loading: false, error: '' });
        if (shouldPoll(data)) timer = setTimeout(fetchResource, 3000);
      } catch (reason) {
        if (!controller.signal.aborted) setState((previous) => ({ url, data: previous.data, loading: false, error: scanError(reason) }));
      }
    }
    void fetchResource();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [url, revision, shouldPoll]);
  return state.url === url ? state : { url, data: null, loading: Boolean(url), error: '' };
}
