import LoginScreen from "./components/LoginScreen";
import { useEffect, useState, useCallback } from "react";
import StatsBar from "./components/StatsBar";
import AttackFeed from "./components/AttackFeed";
import Charts from "./components/Charts";
import ServiceStatus from "./components/ServiceStatus";
import TopAttackers from "./components/TopAttackers";
import AlertBanner from "./components/AlertBanner";
import { useWebSocket } from "./hooks/useWebSocket";
import {
  fetchSummary, fetchByService, fetchTopAttackers, fetchAttacks, fetchServices,
} from "./utils/api";

export default function App() {
  const [authed, setAuthed] = useState(!!localStorage.getItem("nullbait_token"));
  const [stats, setStats] = useState(null);
  const [byService, setByService] = useState([]);
  const [attackers, setAttackers] = useState([]);
  const [services, setServices] = useState([]);
  const [events, setEvents] = useState([]);
  const [alert, setAlert] = useState(null);

  const loadAll = useCallback(async () => {
    try {
      const [s, bs, ta, atks, svc] = await Promise.all([
        fetchSummary(), fetchByService(), fetchTopAttackers(), fetchAttacks(50), fetchServices(),
      ]);
      setStats(s);
      setByService(bs);
      setAttackers(ta);
      setEvents(atks);
      setServices(svc);
    } catch (e) {
      // backend might still be warming up — silently retry on next interval
    }
  }, []);

  useEffect(() => {
    loadAll();
    // refresh the slower-moving stats every 10s; the feed itself
    // updates instantly via websocket, this is just for charts/leaderboard
    const interval = setInterval(loadAll, 10000);
    return () => clearInterval(interval);
  }, [loadAll]);

  const { connected } = useWebSocket((msg) => {
    if (msg.type === "attack_event") {
      setEvents((prev) => [msg, ...prev].slice(0, 100));
      if (msg.threat_score >= 75) {
        setAlert({
          title: "Critical threat detected",
          message: `${msg.attacker_ip} on ${msg.service}`,
        });
      }
    }
  });
  if (!authed) {
    return <LoginScreen onLogin={() => setAuthed(true)} />;
  }
  return (
    <div className="min-h-screen bg-nullbg text-gray-100 p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">NullBait</h1>
          <p className="text-gray-500 text-sm">Adaptive honeypot threat dashboard</p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span
            className={`w-2 h-2 rounded-full ${connected ? "bg-green-500" : "bg-red-500"}`}
          />
          <span className="text-gray-400">{connected ? "Live" : "Reconnecting..."}</span>
        </div>
      </div>

      <AlertBanner alert={alert} onDismiss={() => setAlert(null)} />

      <StatsBar stats={stats} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <AttackFeed events={events} />
        </div>
        <div className="space-y-4">
          <ServiceStatus services={services} />
          <TopAttackers attackers={attackers} />
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Charts data={byService} />
      </div>
    </div>
  );
}
