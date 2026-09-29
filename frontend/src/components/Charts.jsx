import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
} from "recharts";

const COLORS = ["#a855f7", "#3b82f6", "#f59e0b", "#ec4899"];

export default function Charts({ data }) {
  const chartData = (data || []).map((d) => ({
    name: d.service,
    value: parseInt(d.count, 10),
  }));

  return (
    <div className="bg-nullcard border border-nullborder rounded-lg p-4 h-[280px]">
      <h3 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wide">
        Attacks by service
      </h3>
      {chartData.length === 0 ? (
        <div className="text-gray-600 text-sm text-center py-12">No data yet</div>
      ) : (
        <ResponsiveContainer width="100%" height="85%">
          <PieChart>
            <Pie
              data={chartData}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              outerRadius={70}
              label={({ name }) => name}
            >
              {chartData.map((_, i) => (
                <Cell key={i} fill={COLORS[i % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ background: "#11161f", border: "1px solid #1f2733" }}
            />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
