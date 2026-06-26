import { useEffect, useState } from 'react';
import { Client, type StoreClient } from '@exowarexyz/sdk';
import { Buffer } from 'buffer';
import './App.css';
import { QMDB_URL, SIMPLEX_URL, SQL_URL } from './env';
import { LogPanel } from './LogPanel';
import { QmdbPanel } from './QmdbPanel';
import { SimplexPanel } from './SimplexPanel';
import { SqlPanel } from './SqlPanel';
import { StorePanel } from './StorePanel';

// Polyfill Buffer for browser environment
declare global {
  interface Window {
    Buffer: typeof Buffer;
  }
}
window.Buffer = Buffer;

// Load environment variables from .env file
const SIMULATOR_URL = import.meta.env.VITE_SIMULATOR_URL;
const TOKEN = import.meta.env.VITE_TOKEN;

interface Notification {
  id: string;
  type: 'success' | 'error';
  title: string;
  message: string;
}

function App() {
  const [storeClient, setStoreClient] = useState<StoreClient | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);

  useEffect(() => {
    const client = new Client(SIMULATOR_URL, TOKEN);
    const store = client.store();
    setStoreClient(store);

    testConnection(client).then((connected) => {
      if (!connected) {
        setNotifications((prev) => [
          ...prev,
          {
            id: Math.random().toString(36).slice(2, 11),
            type: 'error',
            title: 'Connection Failed',
            message: 'Unable to connect to the simulator backend'
          }
        ]);
      }
    });

    const healthCheckInterval = setInterval(() => {
      void testConnection(client);
    }, 30000);

    return () => {
      clearInterval(healthCheckInterval);
    };
  }, []);

  const showNotification = (type: 'success' | 'error', title: string, message: string) => {
    const id = Math.random().toString(36).slice(2, 11);
    const notification: Notification = { id, type, title, message };
    setNotifications((prev) => [...prev, notification]);

    setTimeout(() => {
      setNotifications((prev) => prev.filter((n) => n.id !== id));
    }, 5000);
  };

  const removeNotification = (id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  };

  const testConnection = async (client: Client) => {
    try {
      await client.store().query(undefined, undefined, 1);
      setIsConnected(true);
      return true;
    } catch (e) {
      console.error('Backend connection failed:', e);
      setIsConnected(false);
      return false;
    }
  };

  return (
    <div className="App">
      {notifications.map((notification) => (
        <div key={notification.id} className={`notification ${notification.type}`}>
          <button
            className="notification-close"
            onClick={() => removeNotification(notification.id)}
          >
            ×
          </button>
          <div className="notification-title">{notification.title}</div>
          <div className="notification-message">{notification.message}</div>
        </div>
      ))}

      <div className="header">
        <div className="header-copy">
          <h1>Exoware API Sandbox</h1>
        </div>
        <div className={`status-indicator ${isConnected ? 'status-connected' : 'status-disconnected'}`}>
          <span>●</span>
          {isConnected ? 'Connected' : 'Disconnected'}
        </div>
      </div>

      <div className="primary-panels">
        <StorePanel
          client={storeClient}
          showNotification={showNotification}
          onConnectionLost={() => setIsConnected(false)}
        />
        <LogPanel
          client={storeClient}
          showNotification={showNotification}
          onConnectionLost={() => setIsConnected(false)}
          onConnectionRestored={() => setIsConnected(true)}
        />
      </div>

      {QMDB_URL && <QmdbPanel qmdbUrl={QMDB_URL} showNotification={showNotification} />}
      {SIMPLEX_URL && <SimplexPanel simplexUrl={SIMPLEX_URL} showNotification={showNotification} />}
      {SQL_URL && <SqlPanel sqlUrl={SQL_URL} showNotification={showNotification} />}
    </div>
  );
}

export default App;
