import { AnimatePresence, motion } from "framer-motion";

const SERVICE_COLORS = {
  ssh: "bg-purple-500/20 text-purple-300",
  http: "bg-blue-500/20 text-blue-300",
  ftp: "bg-amber-500/20 text-amber-300",
  api: "bg-pink-500/20 text-pink-300",
};

const LEVEL_DOT = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-gray-500",
};

function timeAgo(ts) {
  const diff = Math.max(0, Date.now() - new Date(ts).getTime());
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  return `${Math.floor(mins / 60)}h ago`;
}

export default function AttackFeed({ events }) {
  return (
    <div className="bg-nullcard border border-nullborder rounded-lg p-4 h-[480px] overflow-y-auto">
      <h3 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wide">
        Live attack feed
      </h3>
      <AnimatePresence initial={false}>
        {events.map((e) => (
          <motion.div
            key={e.id || `${e.attacker_ip}-${e.timestamp}`}
            initial={{ opacity: 0, x: -12 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="flex items-center gap-3 py-2 border-b border-nullborder/60 text-sm"
          >
            <span
              className={`w-2 h-2 rounded-full flex-shrink-0 ${
                LEVEL_DOT[e.threat_level || "low"] || "bg-gray-500"
              }`}
            />
            <span
              className={`px-2 py-0.5 rounded text-xs font-medium uppercase flex-shrink-0 ${
                SERVICE_COLORS[e.service] || "bg-gray-500/20 text-gray-300"
              }`}
            >
              {e.service}
            </span>
            <span className="text-gray-200 font-mono text-xs flex-shrink-0">
              {e.attacker_ip}
            </span>
            <span className="text-gray-500 truncate flex-1">
              {e.event_type === "login_attempt"
                ? `tried ${e.username || "?"} / ${e.password || "?"}`
                : e.event_type}
            </span>
            <span className="text-gray-600 text-xs flex-shrink-0">
              {timeAgo(e.timestamp)}
            </span>
          </motion.div>
        ))}
      </AnimatePresence>
      {events.length === 0 && (
        <div className="text-gray-600 text-sm text-center py-12">
          Waiting for attacks...
        </div>
      )}
    </div>
  );
}
