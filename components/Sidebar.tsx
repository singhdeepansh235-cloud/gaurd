
import React from 'react';
<<<<<<< HEAD
import { LayoutDashboard, Terminal, FileText, Settings, ShieldAlert, Activity, LogOut, MessageSquare } from 'lucide-react';
=======
import { LayoutDashboard, Terminal, FileText, Settings, ShieldAlert, Activity, LogOut } from 'lucide-react';
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onLogout: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab, onLogout }) => {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scan', label: 'Live Scan', icon: Activity },
    { id: 'vulns', label: 'Findings', icon: ShieldAlert },
<<<<<<< HEAD
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'assistant', label: 'AI Assistant', icon: MessageSquare },
=======
    { id: 'reports', label: 'AI Reports', icon: FileText },
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
    { id: 'config', label: 'Configuration', icon: Settings },
  ];

  return (
    <div className="w-20 lg:w-64 h-screen bg-surface border-r border-zinc-800 flex flex-col fixed left-0 top-0 z-50 transition-all duration-300">
      <div className="p-4 lg:p-6 flex items-center justify-center lg:justify-start gap-3 border-b border-zinc-800">
        <div className="w-8 h-8 bg-primary rounded flex items-center justify-center shadow-[0_0_15px_rgba(16,185,129,0.4)]">
          <Terminal className="text-background w-5 h-5" />
        </div>
        <span className="hidden lg:block font-bold text-xl tracking-wider text-white">
          SENTINEL<span className="text-primary">FUZZ</span>
        </span>
      </div>

      <nav className="flex-1 py-6 px-2 space-y-2">
        {menuItems.map((item) => {
          const isActive = activeTab === item.id;
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-center lg:justify-start gap-4 px-4 py-3 rounded-xl transition-all duration-200 group ${
                isActive 
                  ? 'bg-primary/10 text-primary border border-primary/20' 
                  : 'text-muted hover:text-white hover:bg-zinc-800/50'
              }`}
            >
              <Icon className={`w-5 h-5 ${isActive ? 'stroke-2' : 'stroke-1.5'}`} />
              <span className="hidden lg:block font-medium text-sm">{item.label}</span>
              {isActive && (
                <div className="hidden lg:block ml-auto w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
              )}
            </button>
          );
        })}
      </nav>

      <div className="p-4 border-t border-zinc-800 space-y-4">
        <button 
          onClick={onLogout}
          className="w-full flex items-center justify-center lg:justify-start gap-3 px-4 py-2 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg transition-colors text-sm font-medium"
        >
          <LogOut className="w-4 h-4" />
          <span className="hidden lg:inline">Disconnect</span>
        </button>

        <div className="bg-zinc-900/50 rounded-lg p-3 text-xs text-muted flex flex-col gap-1">
          <span className="font-mono hidden lg:inline">v2.5.0-stable</span>
          <span className="hidden lg:inline flex items-center gap-2">
            Status: <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></span> Online
          </span>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
