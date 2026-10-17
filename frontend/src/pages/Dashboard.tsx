import { useEffect, useState, useCallback } from 'react';
import { wafApi, HealthResponse, StatsResponse, MetricsResponse, TimeseriesResponse } from '../services/api';
import { 
  Shield, AlertTriangle, CheckCircle, Activity, Zap, 
  Settings, RefreshCw, ArrowRight, Radio, Cpu, Layers, Play
} from 'lucide-react';
import { 
  LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, 
  Tooltip, ResponsiveContainer 
} from 'recharts';
import { Link } from 'react-router-dom';
import { useTheme } from '../context/ThemeContext';
import { useToast } from '../context/ToastContext';

interface SystemConfig {
  detection_mode: string;
  demo_mode: boolean;
  demo_request_count: number;
  demo_total_requests: number;
  anomaly_threshold: number;
}

const Dashboard = () => {
  const { resolvedTheme } = useTheme();
  const { info } = useToast();

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [timeseries, setTimeseries] = useState<TimeseriesResponse | null>(null);
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshInterval, setRefreshInterval] = useState<number>(5000); // 5s default

  const fetchData = useCallback(async (isManual: boolean = false) => {
    if (isManual) setRefreshing(true);
    try {
      const [healthData, statsData, metricsData, timeseriesData, configData] = await Promise.all([
        wafApi.health(),
        wafApi.stats().catch(() => null),
        wafApi.metrics().catch(() => null),
        wafApi.timeseriesMetrics(20).catch(() => null),
        wafApi.getConfig().catch(() => null),
      ]);
      setHealth(healthData);
      setStats(statsData);
      setMetrics(metricsData);
      setTimeseries(timeseriesData);
      setConfig(configData);
      setError(null);
      if (isManual) info('Dashboard Refreshed', 'Latest metrics synchronized');
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || err.message || 'Failed to connect to WAF API';
      setError(errorMsg);
      console.error('Dashboard fetch error:', err);
    } finally {
      setLoading(false);
      if (isManual) setRefreshing(false);
    }
  }, [info]);

  useEffect(() => {
    fetchData();
    if (refreshInterval > 0) {
      const interval = setInterval(() => fetchData(false), refreshInterval);
      return () => clearInterval(interval);
    }
  }, [fetchData, refreshInterval]);

  // Chart theme configurations
  const isDark = resolvedTheme === 'dark';
  const gridColor = isDark ? '#1e293b' : '#e2e8f0';
  const textColor = isDark ? '#94a3b8' : '#64748b';
  const tooltipStyle = {
    backgroundColor: isDark ? '#0f172a' : '#ffffff',
    borderColor: isDark ? '#334155' : '#cbd5e1',
    borderRadius: '0.75rem',
    color: isDark ? '#f8fafc' : '#0f172a',
    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.3)',
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[70vh]">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-slate-500 dark:text-slate-400 font-medium">Initializing Security Dashboard...</p>
        </div>
      </div>
    );
  }

  if (error && !health) {
    return (
      <div className="p-6 max-w-7xl mx-auto flex items-center justify-center min-h-[60vh]">
        <div className="text-center p-8 bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-900/50 rounded-2xl max-w-md backdrop-blur-sm">
          <AlertTriangle className="mx-auto mb-4 text-rose-600 dark:text-rose-400" size={48} />
          <h2 className="text-xl font-bold text-rose-900 dark:text-rose-100 mb-2">Connection Error</h2>
          <p className="text-rose-700 dark:text-rose-300 mb-5 text-sm">{error}</p>
          <button
            onClick={() => {
              setLoading(true);
              setError(null);
              fetchData(true);
            }}
            className="btn btn-primary bg-rose-600 hover:bg-rose-500"
          >
            Retry Connection
          </button>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-4">
            Verify the FastAPI server is running with <code className="px-1.5 py-0.5 rounded bg-slate-200 dark:bg-dark-800 font-mono">python api/waf_api.py</code>
          </p>
        </div>
      </div>
    );
  }

  const anomalyRate = metrics && metrics.total_requests > 0 
    ? ((metrics.anomalous_requests / metrics.total_requests) * 100).toFixed(1) 
    : '0.0';
  const detectionRate = metrics?.detection_rate?.toFixed(1) || '100.0';

  const totalRequests = metrics?.total_requests || stats?.total_requests || 0;
  const anomalousRequests = metrics?.anomalous_requests || stats?.anomalous_requests || 0;
  const avgLatency = metrics?.latency_p95 || stats?.p95_latency_ms || 0;
  const p50Latency = stats?.p50_latency_ms || 0;
  const p99Latency = stats?.p99_latency_ms || 0;
  const avgScore = metrics?.avg_anomaly_score || stats?.average_score || 0;
  const cacheHitRate = stats?.cache_hit_rate || 0;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fadeIn">
      {/* Top Header & Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-white">
              Security Overview
            </h1>
            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-primary-50 dark:bg-primary-950/60 text-primary-600 dark:text-primary-400 border border-primary-200 dark:border-primary-800/50">
              <span className="w-1.5 h-1.5 rounded-full bg-primary-500 live-pulse"></span>
              Live ML Model
            </span>
          </div>
          <p className="text-slate-600 dark:text-slate-400 text-sm mt-1">
            Real-time Transformer HTTP anomaly inspection & threat mitigation
          </p>
        </div>

        {/* Action controls & Refresh selector */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Refresh rate pill */}
          <div className="flex items-center rounded-xl bg-white dark:bg-dark-900 border border-slate-200 dark:border-dark-700/80 p-1 text-xs shadow-xs">
            <span className="px-2 text-slate-400 font-medium hidden md:inline">Auto-refresh:</span>
            {[
              { label: 'Off', val: 0 },
              { label: '3s', val: 3000 },
              { label: '5s', val: 5000 },
              { label: '10s', val: 10000 },
            ].map((item) => (
              <button
                key={item.label}
                onClick={() => setRefreshInterval(item.val)}
                className={`px-2.5 py-1 rounded-lg font-medium transition-all ${
                  refreshInterval === item.val
                    ? 'bg-primary-600 text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                {item.label}
              </button>
            ))}
            <button
              onClick={() => fetchData(true)}
              className="p-1 text-slate-500 hover:text-slate-900 dark:hover:text-white ml-1 rounded-lg"
              title="Manual Refresh"
            >
              <RefreshCw size={14} className={refreshing ? 'animate-spin text-primary-500' : ''} />
            </button>
          </div>

          {/* Policy Mode Badge */}
          {config && (
            <div className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 border shadow-xs ${
              config.detection_mode === 'block' 
                ? 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/40 dark:text-rose-300 dark:border-rose-900/50' 
                : config.detection_mode === 'detect'
                ? 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-900/50'
                : 'bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-950/40 dark:text-sky-300 dark:border-sky-900/50'
            }`}>
              <Shield size={14} />
              <span className="capitalize">{config.detection_mode} Mode</span>
            </div>
          )}

          {/* Model state pill */}
          {health && (
            <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border shadow-xs ${
              health.model_loaded 
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-900/50' 
                : 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/40 dark:text-rose-300 dark:border-rose-900/50'
            }`}>
              <CheckCircle size={14} />
              <span>{health.status.toUpperCase()}</span>
            </div>
          )}
        </div>
      </div>

      {/* Quick Launch Cards Banner */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link
          to="/simulation"
          className="card group hover:border-primary-500/50 dark:hover:border-primary-500/50 flex items-center justify-between p-4 cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-rose-500/10 text-rose-500 dark:text-rose-400 group-hover:scale-110 transition-transform">
              <Zap size={22} />
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-900 dark:text-white">Attack Simulator</h4>
              <p className="text-xs text-slate-500 dark:text-slate-400">Launch SQLi, XSS or custom payloads</p>
            </div>
          </div>
          <ArrowRight size={18} className="text-slate-400 group-hover:text-primary-500 group-hover:translate-x-1 transition-all" />
        </Link>

        <Link
          to="/live"
          className="card group hover:border-primary-500/50 dark:hover:border-primary-500/50 flex items-center justify-between p-4 cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-500 dark:text-emerald-400 group-hover:scale-110 transition-transform">
              <Radio size={22} />
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-900 dark:text-white">Live Monitoring</h4>
              <p className="text-xs text-slate-500 dark:text-slate-400">Inspect real-time stream & payloads</p>
            </div>
          </div>
          <ArrowRight size={18} className="text-slate-400 group-hover:text-primary-500 group-hover:translate-x-1 transition-all" />
        </Link>

        <Link
          to="/settings"
          className="card group hover:border-primary-500/50 dark:hover:border-primary-500/50 flex items-center justify-between p-4 cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-indigo-500/10 text-indigo-500 dark:text-indigo-400 group-hover:scale-110 transition-transform">
              <Settings size={22} />
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-900 dark:text-white">WAF Configuration</h4>
              <p className="text-xs text-slate-500 dark:text-slate-400">Tune thresholds & demo traffic</p>
            </div>
          </div>
          <ArrowRight size={18} className="text-slate-400 group-hover:text-primary-500 group-hover:translate-x-1 transition-all" />
        </Link>
      </div>

      {/* Primary Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Requests"
          value={totalRequests.toLocaleString()}
          icon={Activity}
          variant="blue"
          subtitle="Processed traffic"
        />
        <StatCard
          title="Anomalies Detected"
          value={anomalousRequests.toLocaleString()}
          icon={AlertTriangle}
          variant="red"
          subtitle={`${anomalyRate}% of traffic`}
        />
        <StatCard
          title="Detection Rate"
          value={`${detectionRate}%`}
          icon={Shield}
          variant="green"
          subtitle="Benign profile match"
        />
        <StatCard
          title="Latency (P95)"
          value={`${avgLatency.toFixed(0)}ms`}
          icon={Zap}
          variant="yellow"
          subtitle={`P50: ${p50Latency.toFixed(0)}ms | P99: ${p99Latency.toFixed(0)}ms`}
        />
      </div>

      {/* Real-time Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Anomaly Score Trend */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">
                Anomaly Score Trend
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Score threshold boundary at {config?.anomaly_threshold || 0.75}
              </p>
            </div>
            {timeseries?.is_live && (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-500">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 live-pulse"></span>
                LIVE
              </span>
            )}
          </div>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={timeseries?.score_trend || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
              <XAxis dataKey="time" stroke={textColor} fontSize={11} tickLine={false} />
              <YAxis domain={[0, 1]} stroke={textColor} fontSize={11} tickLine={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area 
                type="monotone" 
                dataKey="score" 
                stroke="#ef4444" 
                strokeWidth={2}
                fillOpacity={1} 
                fill="url(#scoreGrad)" 
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Request Volume Distribution */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">
                Request Volume
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Benign traffic vs anomalous threats
              </p>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <span className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Benign
              </span>
              <span className="flex items-center gap-1.5 text-rose-600 dark:text-rose-400 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span> Anomalous
              </span>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={timeseries?.volume_trend || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
              <XAxis dataKey="time" stroke={textColor} fontSize={11} tickLine={false} />
              <YAxis stroke={textColor} fontSize={11} tickLine={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Line type="monotone" dataKey="benign" stroke="#22c55e" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="anomalous" stroke="#ef4444" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Model Specs & Performance Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Model Architecture Info Card */}
        <div className="card lg:col-span-2 border-primary-200/80 dark:border-primary-900/40 bg-gradient-to-br from-white to-primary-50/30 dark:from-dark-900 dark:to-primary-950/20">
          <div className="flex items-start gap-4">
            <div className="p-3 rounded-2xl bg-primary-600/10 text-primary-600 dark:text-primary-400 glow-primary">
              <Cpu size={32} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <h3 className="text-base font-bold text-slate-900 dark:text-white">
                  DistilBERT Anomaly Detection Engine
                </h3>
                <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-primary-100 dark:bg-primary-900/60 text-primary-800 dark:text-primary-300">
                  Zero-Day Ready
                </span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                Trained exclusively on benign HTTP semantics to catch zero-day exploits through token reconstruction loss.
              </p>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 pt-4 border-t border-slate-200/60 dark:border-dark-700/60">
                <div className="p-2 rounded-lg bg-slate-50 dark:bg-dark-800/60">
                  <span className="text-[11px] text-slate-500 dark:text-slate-400">Architecture</span>
                  <p className="text-sm font-bold text-slate-900 dark:text-white mt-0.5">DistilBERT</p>
                </div>
                <div className="p-2 rounded-lg bg-slate-50 dark:bg-dark-800/60">
                  <span className="text-[11px] text-slate-500 dark:text-slate-400">Parameters</span>
                  <p className="text-sm font-bold text-slate-900 dark:text-white mt-0.5">90.7M</p>
                </div>
                <div className="p-2 rounded-lg bg-slate-50 dark:bg-dark-800/60">
                  <span className="text-[11px] text-slate-500 dark:text-slate-400">Engine Uptime</span>
                  <p className="text-sm font-bold text-slate-900 dark:text-white mt-0.5">
                    {health ? formatUptime(health.uptime_seconds) : 'N/A'}
                  </p>
                </div>
                <div className="p-2 rounded-lg bg-slate-50 dark:bg-dark-800/60">
                  <span className="text-[11px] text-slate-500 dark:text-slate-400">Version</span>
                  <p className="text-sm font-bold text-slate-900 dark:text-white mt-0.5">
                    {health?.version || 'v1.0.0'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Real-time Cache & Score Stats */}
        <div className="card flex flex-col justify-between">
          <h3 className="text-base font-bold text-slate-900 dark:text-white mb-3">
            Inference Performance
          </h3>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span className="text-slate-500 dark:text-slate-400">Cache Hit Rate</span>
                <span className="text-slate-900 dark:text-white">{(cacheHitRate * 100).toFixed(1)}%</span>
              </div>
              <div className="h-2 rounded-full bg-slate-100 dark:bg-dark-800 overflow-hidden">
                <div 
                  className="h-full bg-primary-600 rounded-full transition-all duration-500" 
                  style={{ width: `${Math.min(cacheHitRate * 100, 100)}%` }} 
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span className="text-slate-500 dark:text-slate-400">Average Anomaly Score</span>
                <span className="text-slate-900 dark:text-white">{avgScore.toFixed(3)} / 1.000</span>
              </div>
              <div className="h-2 rounded-full bg-slate-100 dark:bg-dark-800 overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-500 ${
                    avgScore > 0.7 ? 'bg-rose-500' : avgScore > 0.4 ? 'bg-amber-500' : 'bg-emerald-500'
                  }`} 
                  style={{ width: `${Math.min(avgScore * 100, 100)}%` }} 
                />
              </div>
            </div>

            <div className="pt-2 border-t border-slate-100 dark:border-dark-700/60 flex items-center justify-between text-xs">
              <span className="text-slate-500 dark:text-slate-400">P99 Latency SLA</span>
              <span className="font-bold text-slate-900 dark:text-white">{p99Latency.toFixed(0)} ms</span>
            </div>
          </div>
        </div>
      </div>

      {/* Security Principles Bar */}
      <div className="card">
        <h3 className="text-base font-bold text-slate-900 dark:text-white mb-4">
          Core Security Architecture
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <SecurityPrinciple
            icon={Shield}
            title="Defense in Depth"
            description="Multi-tier defense combining input sanitization, rate limiting, and deep learning."
          />
          <SecurityPrinciple
            icon={CheckCircle}
            title="Zero Trust Model"
            description="Zero implicit trust. Every incoming payload is normalized and tokenized."
          />
          <SecurityPrinciple
            icon={Activity}
            title="Statistical Detection"
            description="Independent from static signatures, capable of identifying unseen 0-day payloads."
          />
        </div>
      </div>
    </div>
  );
};

// Subcomponents
interface StatCardProps {
  title: string;
  value: string;
  icon: any;
  variant: 'blue' | 'red' | 'green' | 'yellow';
  subtitle?: string;
}

const StatCard = ({ title, value, icon: Icon, variant, subtitle }: StatCardProps) => {
  const styles = {
    blue: {
      bg: 'bg-primary-500/10 text-primary-600 dark:text-primary-400 border-primary-500/20',
      border: 'hover:border-primary-500/40',
    },
    red: {
      bg: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20',
      border: 'hover:border-rose-500/40',
    },
    green: {
      bg: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20',
      border: 'hover:border-emerald-500/40',
    },
    yellow: {
      bg: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20',
      border: 'hover:border-amber-500/40',
    },
  };

  const style = styles[variant];

  return (
    <div className={`card transition-all duration-200 ${style.border}`}>
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{title}</p>
          <p className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white mt-1.5 truncate">{value}</p>
          {subtitle && (
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-medium">{subtitle}</p>
          )}
        </div>
        <div className={`p-2.5 rounded-xl border ${style.bg} flex-shrink-0 ml-3`}>
          <Icon size={22} />
        </div>
      </div>
    </div>
  );
};

const SecurityPrinciple = ({ icon: Icon, title, description }: { icon: any; title: string; description: string }) => (
  <div className="flex gap-3.5 p-4 bg-slate-50/80 dark:bg-dark-850/60 rounded-xl border border-slate-200/60 dark:border-dark-700/60">
    <div className="p-2 rounded-lg bg-primary-500/10 text-primary-600 dark:text-primary-400 flex-shrink-0 self-start">
      <Icon size={20} />
    </div>
    <div>
      <h4 className="text-sm font-bold text-slate-900 dark:text-white">{title}</h4>
      <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 leading-relaxed">{description}</p>
    </div>
  </div>
);

const formatUptime = (seconds: number): string => {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
};

export default Dashboard;
