const LEVEL_BADGE = {
  critical: "bg-red-500/20 text-red-400",
  high: "bg-orange-500/20 text-orange-400",
  medium: "bg-yellow-500/20 text-yellow-400",
  low: "bg-gray-500/20 text-gray-400",
};

export default function TopAttackers({ attackers }) {
  return (
    <div className="bg-nullcard border border-nullborder rounded-lg p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wide">
        Top attackers
      </h3>
      <div className="space-y-2">
        {(attackers || []).map((a) => (
          <div
            key={a.attacker_ip}
            className="flex items-center justify-between text-sm py-1"
          >
            <div>
              <div className="text-gray-200 font-mono text-xs">{a.attacker_ip}</div>
              <div className="text-gray-600 text-xs">
                {a.country || "Unknown"} · {a.total_events} events
              </div>
            </div>
            <span
              className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${
                LEVEL_BADGE[a.threat_level] || LEVEL_BADGE.low
              }`}
            >
              {a.threat_level || "low"}
            </span>
          </div>
        ))}
        {(!attackers || attackers.length === 0) && (
          <div className="text-gray-600 text-xs">No attackers yet</div>
        )}
      </div>
    </div>
  );
}
