const STATUS_COLOR = {
  healthy: "bg-green-500",
  degraded: "bg-yellow-500",
  down: "bg-red-500",
};

export default function ServiceStatus({ services }) {
  return (
    <div className="bg-nullcard border border-nullborder rounded-lg p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wide">
        Service health
      </h3>
      <div className="space-y-2">
        {(services || []).map((s) => (
          <div key={s.service} className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <span
                className={`w-2 h-2 rounded-full ${STATUS_COLOR[s.status] || "bg-gray-500"}`}
              />
              <span className="text-gray-300 uppercase text-xs font-medium">
                {s.service}
              </span>
            </div>
            <span className="text-gray-500 text-xs capitalize">{s.status}</span>
          </div>
        ))}
        {(!services || services.length === 0) && (
          <div className="text-gray-600 text-xs">No service data yet</div>
        )}
      </div>
    </div>
  );
}
