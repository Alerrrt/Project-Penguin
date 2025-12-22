import React, { useMemo } from 'react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import type { VulnerabilityData } from './VulnerabilityList';

interface SecurityPostureChartProps {
  vulnerabilities: VulnerabilityData[];
  loading?: boolean;
}

const COLORS = ['#22c55e', '#facc15', '#ef4444']; // green, yellow, red

const SecurityPostureChart: React.FC<SecurityPostureChartProps> = ({ vulnerabilities, loading }) => {
  // Calculate counts in real time
  const { passed, warning, failed } = useMemo(() => {
    let warning = 0, failed = 0;
    vulnerabilities.forEach(vuln => {
      if (vuln.severity === 'Critical' || vuln.severity === 'High') failed++;
      else if (vuln.severity === 'Medium' || vuln.severity === 'Low') warning++;
    });
    // Passed is a placeholder: you may want to use total checks - (warning+failed) if available
    const passed = Math.max(0, 100 - (warning + failed));
    return { passed, warning, failed };
  }, [vulnerabilities]);

  const data = [
    { name: 'Passed', value: passed },
    { name: 'Warnings', value: warning },
    { name: 'Failed', value: failed },
  ];

  const isLoading = loading || (vulnerabilities.length === 0);

  return (
    <div className="w-full h-64 bg-surface rounded-lg shadow flex flex-col items-center justify-center p-4">
      <h2 className="text-lg font-bold mb-2">Overall Security Posture</h2>
      {isLoading ? (
        <div className="flex flex-col items-center justify-center h-full w-full animate-pulse">
          <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mb-4" />
          <p className="text-textSecondary text-sm">Waiting for scan results...</p>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height="90%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              outerRadius={70}
              label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
              isAnimationActive={true}
            >
              {data.map((_, idx) => (
                <Cell key={`cell-${idx}`} fill={COLORS[idx % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip formatter={(value: number, name: string) => [`${value}`, name]} />
            <Legend verticalAlign="bottom" height={36} />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  );
};

export default SecurityPostureChart; 