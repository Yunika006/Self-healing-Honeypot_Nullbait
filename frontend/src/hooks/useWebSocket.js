import { useEffect, useRef, useState, useCallback } from "react";

const WS_URL = process.env.REACT_APP_WS_URL || "ws://localhost:8000";

export function useWebSocket(onMessage) {
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const reconnectTimer = useRef(null);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  const connect = useCallback(() => {
    const token = localStorage.getItem("nullbait_token");
    const ws = new WebSocket(`${WS_URL}/ws/events?token=${token}`);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
    };

    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        onMessageRef.current(data);
      } catch (e) {
        // ignore malformed messages rather than crashing the dashboard
      }
    };

    ws.onclose = () => {
      setConnected(false);
      // try again in 3 seconds — handles backend restarts gracefully
      reconnectTimer.current = setTimeout(connect, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };
  }, [connect]);

  return { connected };
}
