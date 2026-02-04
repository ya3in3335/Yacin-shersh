
import React from 'react';
import { LineChart, Line, ResponsiveContainer, YAxis } from 'recharts';
import { SystemStats } from '../types';

interface StatsPanelProps {
  stats: SystemStats;
  title: string;
  history: { value: number }[];
  color: string;
}

const StatsPanel: React.FC<StatsPanelProps> = ({ stats, title, history, color }) => {
  const currentValue = title === "CPU" ? stats.cpu : 
                       title === "RAM" ? stats.memory : 
                       title === "TEMP" ? stats.temperature : stats.network;

  return (
    <div className="bg-black/40 border-r border-cyan-500/30 p-4 w-64 backdrop-blur-sm">
      <div className="flex justify-between items-center mb-2">
        <h3 className="text-xs font-bold tracking-tighter opacity-80">{title} ANALYSIS</h3>
        <span className="text-xs font-mono" style={{ color }}>{currentValue.toFixed(1)}%</span>
      </div>
      
      <div className="h-16 w-full opacity-60">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={history}>
            <Line 
              type="monotone" 
              dataKey="value" 
              stroke={color} 
              strokeWidth={1} 
              dot={false} 
              isAnimationActive={false}
            />
            <YAxis hide domain={[0, 100]} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="mt-2 flex gap-1 h-1">
        {[...Array(10)].map((_, i) => (
          <div 
            key={i} 
            className={`flex-1 h-full ${i/10 < currentValue/100 ? 'bg-cyan-500 shadow-[0_0_5px_#00f2ff]' : 'bg-cyan-950'}`}
          />
        ))}
      </div>
    </div>
  );
};

export default StatsPanel;
