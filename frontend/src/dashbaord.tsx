import { useEffect, useState } from 'react';
import { wafApi, HealthResponse, StatsResponse, MetricsResponse, TimeseriesResponse } from '../services/api';
import { Shield, AlertTriangle, CheckCircle, Activity, Clock, Zap, Settings } from 'lucide-react';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Link } from 'react-router-dom';

interface SystemConfig {
  detection_mode: string;
  demo_mode: boolean;
  demo_request_count: number;
  demo_total_requests: number;
  anomaly_threshold: number;
}const Dashboard = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [timeseries, setTimeseries] = useState<TimeseriesResponse | null>(null);
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setError(null);
      const [healthData, statsData, metricsData, timeseriesData, configData] = await Promise.all([
        wafApi.health(),
        wafApi.stats().catch(() => null),
        wafApi.metrics(),
        wafApi.timeseriesMetrics(20),
        wafApi.getConfig().catch(() => null),
      ]);
      setHealth(healthData);
      setStats(statsData);
      setMetrics(metricsData);
      setTimeseries(timeseriesData);
      setConfig(configData);
      setError(null);
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || err.message || 'Failed to connect to WAF API';
      setError(errorMsg);
      console.error('Dashboard fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000); // Refresh every 5s
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading WAF Dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center p-8 bg-red-50 rounded-lg max-w-md">
          <AlertTriangle className="mx-auto mb-4 text-red-600" size={48} />
          <h2 className="text-xl font-bold text-red-900 mb-2">Connection Error</h2>
          <p className="text-red-700 mb-4">{error}</p>
          <button
            onClick={() => {
              setLoading(true);
              setError(null);
              fetchData();
            }}
            className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
          >
            Retry Connection
          </button>
          <p className="text-sm text-gray-600 mt-4">
            Make sure the backend API is running on {(import.meta as any).env?.VITE_API_URL || (window.location.hostname === 'transformer-waf.onrender.com' ? 'https://transformer-waf-api.onrender.com' : 'http://127.0.0.1:8000')}
          </p>
        </div>
      </div>
    );
  }

  const anomalyRate = metrics && metrics.total_requests > 0 
    ? ((metrics.anomalous_requests / metrics.total_requests) * 100).toFixed(1) 
    : '0.0';
  const detectionRate = metrics?.detection_rate?.toFixed(1) || '100.0';

  // Use metrics data (real-time) with fallback to stats
  const totalRequests = metrics?.total_requests || stats?.total_requests || 0;
  const anomalousRequests = metrics?.anomalous_requests || stats?.anomalous_requests || 0;
  const avgLatency = metrics?.latency_p95 || stats?.p95_latency_ms || 0;
  const p50Latency = stats?.p50_latency_ms || 0;
  const p99Latency = stats?.p99_latency_ms || 0;
  const avgScore = metrics?.avg_anomaly_score || stats?.average_score || 0;
  const cacheHitRate = stats?.cache_hit_rate || 0;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="text-gray-600 mt-1">Real-time Transformer-based WAF monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          {config && (
            <div className="flex items-center gap-2">
              <div className={`px-3 py-1 rounded-lg text-sm font-semibold ${
                config.detection_mode === 'block' 
                  ? 'bg-red-100 text-red-800' 
                  : config.detection_mode === 'detect'
                  ? 'bg-yellow-100 text-yellow-800'
                  : 'bg-blue-100 text-blue-800'
              }`}>
                {config.detection_mode === 'block' && '🛡️ Block Mode'}
                {config.detection_mode === 'detect' && '⚠️ Detect & Alert'}
                {config.detection_mode === 'monitor' && '👁️ Monitor Only'}
              </div>
              {config.demo_mode && (
                <div className="px-3 py-1 rounded-lg text-sm font-semibold bg-purple-100 text-purple-800">
                  🎮 Demo: {config.demo_request_count}/{config.demo_total_requests}
                </div>
              )}
              <Link 
                to="/settings"
                className="p-2 rounded-lg bg-gray-100 hover:bg-gray-200 transition-colors"
                title="Configure Settings"
              >
                <Settings size={20} className="text-gray-700" />
              </Link>
            </div>
          )}
          {health && (
            <div className={`flex items-center gap-2 px-4 py-2 rounded-lg ${health.model_loaded ? 'bg-success-100 text-success-800' : 'bg-danger-100 text-danger-800'}`}>
              {health.model_loaded ? <CheckCircle size={20} /> : <AlertTriangle size={20} />}
              <span className="font-semibold">{health.status.toUpperCase()}</span>
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="bg-danger-50 border border-danger-200 text-danger-800 px-4 py-3 rounded-lg">
          <div className="flex items-center gap-2">
            <AlertTriangle size={20} />
            <span>{error}</span>
          </div>
        </div>
      )}
