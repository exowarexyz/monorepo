import { useEffect, useState } from 'react';

export interface NotificationFn {
  (type: 'success' | 'error', title: string, message: string): void;
}

/** Whether the server at `url` answers `/health`, checked again when `url` changes. */
export function useHealth(url: string): boolean {
  const [isConnected, setIsConnected] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const response = await fetch(`${url.replace(/\/$/, '')}/health`, {
          signal: controller.signal,
        });
        setIsConnected(response.ok);
      } catch {
        setIsConnected(false);
      }
    })();
    return () => controller.abort();
  }, [url]);
  return isConnected;
}
