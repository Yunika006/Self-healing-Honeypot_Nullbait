import { motion } from "framer-motion";

const cards = [
  { key: "total_events", label: "Total events", color: "text-blue-400" },
  { key: "unique_attackers", label: "Unique attackers", color: "text-amber-400" },
  { key: "credentials_captured", label: "Credentials captured", color: "text-pink-400" },
  { key: "critical_threats", label: "Critical threats", color: "text-red-500" },
];

export default function StatsBar({ stats }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      {cards.map((c) => (
        <motion.div
          key={c.key}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-nullcard border border-nullborder rounded-lg p-4"
        >
          <div className={`text-3xl font-bold ${c.color}`}>
            {stats ? stats[c.key] ?? 0 : "—"}
          </div>
          <div className="text-xs text-gray-500 mt-1 uppercase tracking-wide">
            {c.label}
          </div>
        </motion.div>
      ))}
    </div>
  );
}
