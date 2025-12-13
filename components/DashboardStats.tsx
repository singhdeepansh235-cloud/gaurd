<<<<<<< HEAD

import React from 'react';
import { ScanStats } from '../types';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie, BarChart, Bar } from 'recharts';
import { Activity, Globe, ShieldAlert, Zap, Server, Cpu, Network, Clock } from 'lucide-react';
=======
import React from 'react';
import { ScanStats } from '../types';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie } from 'recharts';
import { Activity, Globe, ShieldAlert, Zap } from 'lucide-react';
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268

interface DashboardStatsProps {
  stats: ScanStats;
}

const DashboardStats: React.FC<DashboardStatsProps> = ({ stats }) => {
  const severityData = [
    { name: 'Critical', value: stats.criticalCount, color: '#ef4444' },
    { name: 'High', value: stats.highCount, color: '#f97316' },
    { name: 'Medium', value: stats.vulnsFound - stats.criticalCount - stats.highCount, color: '#eab308' },
  ].filter(d => d.value > 0);

<<<<<<< HEAD
  // Mock data for the area chart to make it look alive
  const trafficData = Array.from({ length: 20 }, (_, i) => ({
    name: `T-${20 - i}`,
    requests: Math.floor(Math.random() * (stats.requests / 10 || 100)) + 50,
    errors: Math.floor(Math.random() * 10)
  }));

  const StatCard = ({ icon: Icon, label, value, subtext, color, trend }: any) => (
    <div className="bg-zinc-900/40 backdrop-blur-md p-6 rounded-xl border border-zinc-800/60 shadow-lg relative overflow-hidden group hover:border-zinc-700 transition-all duration-300">
      <div className={`absolute top-0 right-0 w-24 h-24 ${color.replace('text-', 'bg-')}/5 rounded-full blur-2xl -mr-12 -mt-12 transition-all group-hover:bg-opacity-10`}></div>
      
      <div className="flex justify-between items-start mb-4 relative z-10">
        <div className={`p-3 rounded-lg bg-black/40 border border-zinc-800 ${color} shadow-inner`}>
          <Icon className="w-6 h-6" />
        </div>
        {trend && (
           <span className="text-xs font-mono bg-emerald-500/10 text-emerald-400 px-2 py-1 rounded border border-emerald-500/20">
             {trend}
           </span>
        )}
      </div>
      
      <div className="relative z-10">
        <h3 className="text-3xl font-bold text-white font-mono tracking-tight">{value}</h3>
        <p className="text-sm text-zinc-500 font-medium uppercase tracking-wider mt-1">{label}</p>
        {subtext && <p className="text-xs text-zinc-600 mt-2">{subtext}</p>}
      </div>
=======
  const requestData = [
    { name: 'DNS', count: Math.floor(stats.requests * 0.2) },
    { name: 'HTTP', count: Math.floor(stats.requests * 0.6) },
    { name: 'Fuzz', count: Math.floor(stats.requests * 0.2) },
  ];

  const StatCard = ({ icon: Icon, label, value, color }: any) => (
    <div className="bg-surface p-5 rounded-xl border border-zinc-800">
      <div className="flex items-center justify-between mb-4">
        <div className={`p-2 rounded-lg ${color} bg-opacity-10`}>
          <Icon className={`w-5 h-5 ${color.replace('bg-', 'text-')}`} />
        </div>
      </div>
      <h3 className="text-2xl font-bold text-white">{value}</h3>
      <p className="text-sm text-zinc-500">{label}</p>
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
    </div>
  );

  return (
<<<<<<< HEAD
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Top Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard 
          icon={Activity} 
          label="Total Requests" 
          value={stats.requests.toLocaleString()} 
          subtext={`${(stats.requests / (stats.duration || 1)).toFixed(1)} req/sec avg`}
          color="text-blue-500" 
          trend="+12%"
        />
        <StatCard 
          icon={Globe} 
          label="Attack Surface" 
          value={stats.subdomains} 
          subtext="Subdomains & Assets"
          color="text-purple-500"
        />
        <StatCard 
          icon={ShieldAlert} 
          label="Vulnerabilities" 
          value={stats.vulnsFound} 
          subtext={`${stats.criticalCount} Critical identified`}
          color="text-red-500"
          trend={stats.vulnsFound > 0 ? "CRITICAL" : "SAFE"}
        />
        <StatCard 
          icon={Zap} 
          label="Engine Efficiency" 
          value="99.9%" 
          subtext="Uptime & Reliability"
          color="text-emerald-500"
        />
      </div>

      {/* Main Charts Area */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Network Traffic Chart */}
        <div className="lg:col-span-2 bg-surface rounded-xl border border-zinc-800 p-6 shadow-lg">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Network className="w-5 h-5 text-blue-500" /> Network Traffic Analysis
              </h3>
              <p className="text-xs text-zinc-500 mt-1">Real-time HTTP request throughput</p>
            </div>
            <div className="flex gap-2">
              <span className="text-xs px-2 py-1 bg-blue-500/10 text-blue-400 rounded border border-blue-500/20">HTTPS</span>
              <span className="text-xs px-2 py-1 bg-zinc-800 text-zinc-400 rounded border border-zinc-700">WSS</span>
            </div>
          </div>
          
          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficData}>
                <defs>
                  <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" stroke="#52525b" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis stroke="#52525b" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#09090b', border: '1px solid #27272a', borderRadius: '8px', color: '#fff' }}
                  itemStyle={{ color: '#fff' }}
                />
                <Area type="monotone" dataKey="requests" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorRequests)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-surface rounded-xl border border-zinc-800 p-6 shadow-lg flex flex-col">
          <h3 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-500" /> Threat Distribution
          </h3>
          <p className="text-xs text-zinc-500 mb-6">Vulnerability severity classification</p>
          
          <div className="flex-1 min-h-[200px] relative">
=======
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard icon={Activity} label="Requests Sent" value={stats.requests.toLocaleString()} color="bg-blue-500" />
        <StatCard icon={Globe} label="Subdomains" value={stats.subdomains} color="bg-purple-500" />
        <StatCard icon={ShieldAlert} label="Vulnerabilities" value={stats.vulnsFound} color="bg-red-500" />
        <StatCard icon={Zap} label="Efficiency" value="98%" color="bg-emerald-500" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-surface p-6 rounded-xl border border-zinc-800">
          <h3 className="text-lg font-semibold text-white mb-6">Vulnerability Distribution</h3>
          <div className="h-64 w-full">
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
<<<<<<< HEAD
                    stroke="none"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#09090b', border: '1px solid #27272a', borderRadius: '8px' }}
=======
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0)" />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#18181b', border: '1px solid #27272a', borderRadius: '8px' }}
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
                    itemStyle={{ color: '#e4e4e7' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
<<<<<<< HEAD
               <div className="absolute inset-0 flex flex-col items-center justify-center text-zinc-600">
                 <div className="w-16 h-16 rounded-full border-2 border-zinc-800 border-dashed animate-spin-slow mb-3"></div>
                 <span className="text-sm">System Secure</span>
               </div>
            )}
            
            {/* Center Text Overlay */}
            {severityData.length > 0 && (
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <div className="text-center">
                  <span className="text-3xl font-bold text-white">{stats.vulnsFound}</span>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Total</div>
                </div>
              </div>
            )}
          </div>

          <div className="mt-6 space-y-2">
            <div className="flex justify-between items-center text-sm">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-red-500"></div>
                <span className="text-zinc-300">Critical</span>
              </div>
              <span className="font-mono text-zinc-500">{stats.criticalCount}</span>
            </div>
            <div className="flex justify-between items-center text-sm">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-orange-500"></div>
                <span className="text-zinc-300">High</span>
              </div>
              <span className="font-mono text-zinc-500">{stats.highCount}</span>
            </div>
          </div>
        </div>
      </div>

      {/* System Health Strip */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-zinc-900/30 border border-zinc-800/50 p-3 rounded-lg flex items-center gap-3">
          <div className="p-2 bg-emerald-500/10 rounded text-emerald-500">
            <Server className="w-4 h-4" />
          </div>
          <div>
             <div className="text-xs text-zinc-500 uppercase">System Status</div>
             <div className="text-sm font-medium text-emerald-400">Operational</div>
          </div>
        </div>
        <div className="bg-zinc-900/30 border border-zinc-800/50 p-3 rounded-lg flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 rounded text-blue-500">
            <Cpu className="w-4 h-4" />
          </div>
          <div>
             <div className="text-xs text-zinc-500 uppercase">CPU Load</div>
             <div className="text-sm font-medium text-blue-400">12% (Nominal)</div>
          </div>
        </div>
        <div className="bg-zinc-900/30 border border-zinc-800/50 p-3 rounded-lg flex items-center gap-3">
          <div className="p-2 bg-purple-500/10 rounded text-purple-500">
            <Clock className="w-4 h-4" />
          </div>
          <div>
             <div className="text-xs text-zinc-500 uppercase">Uptime</div>
             <div className="text-sm font-medium text-purple-400">42h 12m 30s</div>
=======
              <div className="flex items-center justify-center h-full text-zinc-600 text-sm">
                No vulnerabilities detected
              </div>
            )}
          </div>
        </div>

        <div className="bg-surface p-6 rounded-xl border border-zinc-800">
          <h3 className="text-lg font-semibold text-white mb-6">Request Traffic (Engine Activity)</h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={requestData}>
                <XAxis dataKey="name" stroke="#71717a" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#71717a" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip 
                  cursor={{fill: '#27272a'}}
                  contentStyle={{ backgroundColor: '#18181b', border: '1px solid #27272a', borderRadius: '8px' }}
                  itemStyle={{ color: '#e4e4e7' }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} barSize={30} />
              </BarChart>
            </ResponsiveContainer>
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
          </div>
        </div>
      </div>
    </div>
  );
};

<<<<<<< HEAD
export default DashboardStats;
=======
export default DashboardStats;
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
