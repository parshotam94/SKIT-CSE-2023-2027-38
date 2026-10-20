import { useState, useEffect, useRef, useMemo } from 'react';
import { 
  Activity, AlertTriangle, Shield, Zap, Wifi, WifiOff, Settings, 
  Search, Pause, Play, Trash2, X, Copy, ExternalLink, Info, Filter 
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { getWsUrl } from '../services/api';
import { useToast } from '../context/ToastContext';

interface DetectionEvent {
  type: string;
  timestamp: string;
  request: {
    ip: string;
    method: string;
    path: string;
    query: string;
    userAgent: string;
    statusCode: number;
  };
  detection: {
    anomalyScore: number;
    isAnomalous: boolean;
    confidence: number;
    threshold: number;
    severity: 'low' | 'medium' | 'high' | 'critical';
  };
  metadata: {
    latency: number;
    modelVersion: string;
  };
}

const LiveMonitoring = () => {
  const { success } = useToast();
  const [events, setEvents] = useState<DetectionEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [isPaused, setIsPaused] = useState(false);
  const isPausedRef = useRef(false);
  isPausedRef.current = isPaused;

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [activeModalEvent, setActiveModalEvent] = useState<DetectionEvent | null>(null);

  const [stats, setStats] = useState({
    totalRequests: 0,
    anomalousRequests: 0,
    avgScore: 0,
    criticalCount: 0
  });

  const wsRef = useRef<WebSocket | null>(null);
  const maxEvents = 150;

  useEffect(() => {
    connectWebSocket();
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const connectWebSocket = () => {
    try {
      const wsUrl = getWsUrl('/ws/live');
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        setConnectionError(null);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'detection') {
            const detectionEvent = data as DetectionEvent;

            // Update stats regardless of pause
            setStats(prev => ({
              totalRequests: prev.totalRequests + 1,
              anomalousRequests: prev.anomalousRequests + (detectionEvent.detection.isAnomalous ? 1 : 0),
              avgScore: ((prev.avgScore * prev.totalRequests) + detectionEvent.detection.anomalyScore) / (prev.totalRequests + 1),
              criticalCount: prev.criticalCount + (detectionEvent.detection.severity === 'critical' ? 1 : 0)
            }));

            // Only append to event list if not paused
            if (!isPausedRef.current) {
              setEvents(prev => [detectionEvent, ...prev].slice(0, maxEvents));
            }
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

      ws.onerror = () => {
        setConnectionError('Connection interrupted');
      };

      ws.onclose = () => {
        setIsConnected(false);
        setTimeout(() => {
          if (!wsRef.current || wsRef.current.readyState === WebSocket.CLOSED) {
            connectWebSocket();
          }
        }, 4000);
      };
    } catch (error: any) {
      setConnectionError(error.message || 'Failed to initialize WebSocket');
    }
  };

  const getScoreColor = (score: number) => {
    if (score > 0.8) return 'text-rose-600 dark:text-rose-400';
    if (score > 0.5) return 'text-amber-600 dark:text-amber-400';
    return 'text-emerald-600 dark:text-emerald-400';
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-rose-100 text-rose-800 border-rose-200 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-900/60';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-950/60 dark:text-orange-300 dark:border-orange-900/60';
      case 'medium':
        return 'bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-900/60';
      default:
        return 'bg-emerald-100 text-emerald-800 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-900/60';
    }
  };

  const copyPayload = (ev: DetectionEvent) => {
    navigator.clipboard.writeText(JSON.stringify(ev, null, 2));
    success('Payload Copied', 'JSON event payload copied to clipboard');
  };

  const filteredEvents = useMemo(() => {
    return events.filter(ev => {
      if (selectedSeverity !== 'all' && ev.detection.severity !== selectedSeverity) {
        return false;
      }
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const combined = `${ev.request.method} ${ev.request.path} ${ev.request.query} ${ev.request.ip} ${ev.request.userAgent}`.toLowerCase();
        return combined.includes(query);
      }
      return true;
    });
  }, [events, selectedSeverity, searchQuery]);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-white">
              Live Monitoring Stream
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/50">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 live-pulse"></span>
              Live Feed
            </span>
          </div>
          <p className="text-slate-600 dark:text-slate-400 text-sm mt-1">
            Real-time WebSocket telemetry for incoming HTTP requests and ML inference verdicts
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/simulation"
            className="btn btn-secondary text-xs flex items-center gap-1.5"
          >
            <Zap size={15} className="text-amber-500" />
            Inject Test Traffic
          </Link>
          <Link
            to="/settings"
            className="p-2 rounded-xl border border-slate-200 dark:border-dark-700 bg-white dark:bg-dark-800 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-dark-700"
            title="Configure Thresholds"
          >
            <Settings size={18} />
          </Link>
        </div>
      </div>

      {/* Model Detection Note Banner */}
      <div className="p-4 bg-sky-50 dark:bg-sky-950/30 border border-sky-200 dark:border-sky-900/50 rounded-xl flex items-start gap-3">
        <Info className="w-5 h-5 text-sky-600 dark:text-sky-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs text-sky-900 dark:text-sky-200 leading-relaxed">
          <span className="font-bold">Deep Learning Semantic Scoring:</span> This system evaluates requests using Transformer reconstruction loss against learned benign models. High scores trigger configurable actions (alerting or blocking). Click on any event below to inspect full headers and token metrics.
        </div>
      </div>

      {/* Connection & Stream Bar */}
      <div className={`p-4 rounded-xl border flex flex-col sm:flex-row items-center justify-between gap-3 ${
        isConnected 
          ? 'bg-emerald-50/70 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-900/40' 
          : 'bg-rose-50/70 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/40'
      }`}>
        <div className="flex items-center gap-2.5">
          {isConnected ? (
            <>
              <div className="p-1.5 rounded-lg bg-emerald-500/20 text-emerald-600 dark:text-emerald-400">
                <Wifi size={18} />
              </div>
              <div>
                <span className="text-sm font-bold text-emerald-900 dark:text-emerald-300 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 live-pulse"></span>
                  WebSocket Stream Active
                </span>
                <p className="text-xs text-emerald-700 dark:text-emerald-400/80">Listening for real-time security events</p>
              </div>
            </>
          ) : (
            <>
              <div className="p-1.5 rounded-lg bg-rose-500/20 text-rose-600 dark:text-rose-400">
                <WifiOff size={18} />
              </div>
              <div>
                <span className="text-sm font-bold text-rose-900 dark:text-rose-300">
                  {connectionError || 'Disconnected - Attempting Reconnect...'}
                </span>
                <p className="text-xs text-rose-700 dark:text-rose-400/80">Check that backend is running on port 8000</p>
              </div>
            </>
          )}
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`btn text-xs px-3 py-1.5 flex items-center gap-1.5 ${
              isPaused 
                ? 'bg-amber-600 hover:bg-amber-500 text-white' 
                : 'btn-secondary'
            }`}
          >
            {isPaused ? <Play size={14} /> : <Pause size={14} />}
            <span>{isPaused ? 'Resume Stream' : 'Pause Stream'}</span>
          </button>
          
          <button
            onClick={() => setEvents([])}
            className="btn btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5"
            title="Clear Stream History"
          >
            <Trash2 size={14} />
            <span>Clear</span>
          </button>

          {!isConnected && (
            <button
              onClick={connectWebSocket}
              className="btn btn-primary text-xs px-3 py-1.5"
            >
              Reconnect
            </button>
          )}
        </div>
      </div>

      {/* Stream Metrics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase">Total Requests</p>
              <p className="text-2xl font-bold text-slate-900 dark:text-white mt-1">{stats.totalRequests}</p>
            </div>
            <div className="p-2.5 rounded-xl bg-primary-500/10 text-primary-500">
              <Activity size={20} />
            </div>
          </div>
        </div>

        <div className="card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase">Anomalous</p>
              <p className="text-2xl font-bold text-amber-500 mt-1">{stats.anomalousRequests}</p>
            </div>
            <div className="p-2.5 rounded-xl bg-amber-500/10 text-amber-500">
              <AlertTriangle size={20} />
            </div>
          </div>
        </div>

        <div className="card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase">Avg Score</p>
              <p className={`text-2xl font-bold mt-1 ${getScoreColor(stats.avgScore)}`}>
                {stats.avgScore.toFixed(3)}
              </p>
            </div>
            <div className="p-2.5 rounded-xl bg-sky-500/10 text-sky-500">
              <Zap size={20} />
            </div>
          </div>
        </div>

        <div className="card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase">Critical Threats</p>
              <p className="text-2xl font-bold text-rose-500 mt-1">{stats.criticalCount}</p>
            </div>
            <div className="p-2.5 rounded-xl bg-rose-500/10 text-rose-500">
              <Shield size={20} />
            </div>
          </div>
        </div>
      </div>

      {/* Stream Controls & Table Card */}
      <div className="card space-y-4">
        {/* Filters & Search Toolbar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pt-1">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-2.5 text-slate-400" size={16} />
            <input
              type="text"
              placeholder="Search by path, method, IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input-field pl-9 text-xs"
            />
          </div>

          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
            <span className="text-slate-400 font-medium mr-1 flex items-center gap-1">
              <Filter size={13} /> Severity:
            </span>
            {['all', 'low', 'medium', 'high', 'critical'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded-lg font-semibold uppercase tracking-wider text-[11px] transition-all ${
                  selectedSeverity === sev
                    ? 'bg-slate-900 text-white dark:bg-primary-600 dark:text-white shadow-xs'
                    : 'bg-slate-100 dark:bg-dark-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-dark-700'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* Live Stream Table */}
        {filteredEvents.length === 0 ? (
          <div className="text-center py-14 border border-dashed border-slate-200 dark:border-dark-700 rounded-xl">
            <Shield className="w-14 h-14 text-slate-300 dark:text-dark-700 mx-auto mb-3" />
            <p className="text-slate-700 dark:text-slate-300 font-semibold text-sm">
              {events.length === 0 ? 'Waiting for incoming HTTP traffic...' : 'No events match your filter criteria'}
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-sm mx-auto">
              {events.length === 0
                ? 'Launch an attack simulation or enable Demo traffic in Settings to generate live events.'
                : 'Try adjusting your search query or severity filter.'}
            </p>
            {events.length === 0 && (
              <Link
                to="/simulation"
                className="btn btn-primary text-xs mt-4 inline-flex items-center gap-1.5"
              >
                <Zap size={14} />
                Simulate Attacks Now
              </Link>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-dark-700/80">
            <table className="min-w-full divide-y divide-slate-200 dark:divide-dark-800">
              <thead className="bg-slate-50 dark:bg-dark-850">
                <tr>
                  <th className="px-3.5 py-2.5 text-left text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Time</th>
                  <th className="px-3.5 py-2.5 text-left text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Method</th>
                  <th className="px-3.5 py-2.5 text-left text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Path</th>
                  <th className="px-3.5 py-2.5 text-left text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Client IP</th>
                  <th className="px-3.5 py-2.5 text-left text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Score</th>
                  <th className="px-3.5 py-2.5 text-left text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Severity</th>
                  <th className="px-3.5 py-2.5 text-left text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Action</th>
                  <th className="px-3.5 py-2.5 text-right text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-dark-800 bg-white dark:bg-dark-900">
                {filteredEvents.map((event, idx) => {
                  const isBlocked = event.detection.isAnomalous;
                  return (
                    <tr
                      key={`${event.timestamp}-${idx}`}
                      onClick={() => setActiveModalEvent(event)}
                      className={`cursor-pointer transition-colors duration-150 ${
                        isBlocked
                          ? 'bg-rose-50/40 dark:bg-rose-950/20 hover:bg-rose-50 dark:hover:bg-rose-950/40'
                          : 'hover:bg-slate-50 dark:hover:bg-dark-800/60'
                      }`}
                    >
                      <td className="px-3.5 py-2.5 text-xs text-slate-500 dark:text-slate-400 font-mono whitespace-nowrap">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-3.5 py-2.5 text-xs font-mono">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                          event.request.method === 'GET' 
                            ? 'bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300' 
                            : event.request.method === 'POST' 
                            ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300' 
                            : 'bg-purple-100 text-purple-800 dark:bg-purple-950/60 dark:text-purple-300'
                        }`}>
                          {event.request.method}
                        </span>
                      </td>
                      <td className="px-3.5 py-2.5 text-xs font-mono text-slate-900 dark:text-slate-200 max-w-xs truncate" title={`${event.request.path}${event.request.query}`}>
                        {event.request.path}
                        {event.request.query && <span className="text-slate-400">{event.request.query}</span>}
                      </td>
                      <td className="px-3.5 py-2.5 text-xs font-mono text-slate-500 dark:text-slate-400 whitespace-nowrap">
                        {event.request.ip}
                      </td>
                      <td className="px-3.5 py-2.5 text-xs font-mono font-bold whitespace-nowrap">
                        <span className={getScoreColor(event.detection.anomalyScore)}>
                          {event.detection.anomalyScore.toFixed(3)}
                        </span>
                      </td>
                      <td className="px-3.5 py-2.5 text-xs whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getSeverityBadgeClass(event.detection.severity)}`}>
                          {event.detection.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-3.5 py-2.5 text-xs font-semibold whitespace-nowrap">
                        {isBlocked ? (
                          <span className="text-rose-600 dark:text-rose-400 flex items-center gap-1 font-bold">
                            🚨 BLOCKED
                          </span>
                        ) : (
                          <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                            ✓ ALLOWED
                          </span>
                        )}
                      </td>
                      <td className="px-3.5 py-2.5 text-xs text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setActiveModalEvent(event);
                          }}
                          className="text-primary-600 dark:text-primary-400 hover:underline text-xs font-medium"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Payload Inspection Modal */}
      {activeModalEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-xs animate-fadeIn">
          <div className="card max-w-2xl w-full max-h-[85vh] flex flex-col p-6 shadow-2xl border border-slate-300 dark:border-dark-700">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-dark-700">
              <div className="flex items-center gap-2.5">
                <div className={`p-2 rounded-xl ${
                  activeModalEvent.detection.isAnomalous 
                    ? 'bg-rose-500/10 text-rose-500' 
                    : 'bg-emerald-500/10 text-emerald-500'
                }`}>
                  <Shield size={22} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-900 dark:text-white">
                    Request Payload Telemetry
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                    {new Date(activeModalEvent.timestamp).toISOString()}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setActiveModalEvent(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-white"
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Content Scrollable Area */}
            <div className="py-4 space-y-4 overflow-y-auto flex-1 text-xs">
              {/* Verdict Summary Bar */}
              <div className={`p-3 rounded-xl border flex items-center justify-between ${
                activeModalEvent.detection.isAnomalous 
                  ? 'bg-rose-50 dark:bg-rose-950/30 border-rose-200 dark:border-rose-900/50' 
                  : 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900/50'
              }`}>
                <div>
                  <span className="font-bold text-sm text-slate-900 dark:text-white block">
                    {activeModalEvent.detection.isAnomalous ? '⚠️ Anomaly Detected' : '✓ Normal Benign Traffic'}
                  </span>
                  <span className="text-slate-600 dark:text-slate-300 text-xs">
                    Confidence: {(activeModalEvent.detection.confidence * 100).toFixed(1)}% | Threshold: {activeModalEvent.detection.threshold}
                  </span>
                </div>
                <span className={`px-3 py-1 rounded-lg font-bold text-xs uppercase ${getSeverityBadgeClass(activeModalEvent.detection.severity)}`}>
                  {activeModalEvent.detection.severity}
                </span>
              </div>

              {/* Anomaly Gauge */}
              <div className="p-3 bg-slate-50 dark:bg-dark-800/70 rounded-xl border border-slate-200 dark:border-dark-700">
                <div className="flex justify-between font-semibold mb-1.5">
                  <span className="text-slate-500 dark:text-slate-400">Model Anomaly Score</span>
                  <span className={`font-mono font-bold ${getScoreColor(activeModalEvent.detection.anomalyScore)}`}>
                    {activeModalEvent.detection.anomalyScore.toFixed(4)} / 1.0000
                  </span>
                </div>
                <div className="h-2.5 rounded-full bg-slate-200 dark:bg-dark-700 overflow-hidden relative">
                  <div
                    className={`h-full rounded-full transition-all duration-300 ${
                      activeModalEvent.detection.anomalyScore > 0.7 ? 'bg-rose-500' : activeModalEvent.detection.anomalyScore > 0.4 ? 'bg-amber-500' : 'bg-emerald-500'
                    }`}
                    style={{ width: `${Math.min(activeModalEvent.detection.anomalyScore * 100, 100)}%` }}
                  />
                </div>
              </div>

              {/* HTTP Request Details */}
              <div className="space-y-2">
                <h4 className="font-bold text-slate-900 dark:text-white uppercase tracking-wider text-[11px]">
                  HTTP Request Spec
                </h4>
                <div className="grid grid-cols-2 gap-2 font-mono">
                  <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-dark-800 border border-slate-200 dark:border-dark-700">
                    <span className="text-[10px] text-slate-400 block">Method</span>
                    <span className="font-bold text-slate-900 dark:text-white">{activeModalEvent.request.method}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-dark-800 border border-slate-200 dark:border-dark-700">
                    <span className="text-[10px] text-slate-400 block">Status Code</span>
                    <span className="font-bold text-slate-900 dark:text-white">{activeModalEvent.request.statusCode}</span>
                  </div>
                  <div className="col-span-2 p-2.5 rounded-lg bg-slate-50 dark:bg-dark-800 border border-slate-200 dark:border-dark-700">
                    <span className="text-[10px] text-slate-400 block">Target Path & Query</span>
                    <span className="font-bold text-slate-900 dark:text-white break-all">
                      {activeModalEvent.request.path}{activeModalEvent.request.query}
                    </span>
                  </div>
                  <div className="col-span-2 p-2.5 rounded-lg bg-slate-50 dark:bg-dark-800 border border-slate-200 dark:border-dark-700">
                    <span className="text-[10px] text-slate-400 block">Client User-Agent</span>
                    <span className="text-slate-700 dark:text-slate-300 break-all">{activeModalEvent.request.userAgent}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="pt-3 border-t border-slate-200 dark:border-dark-700 flex justify-between items-center">
              <button
                onClick={() => copyPayload(activeModalEvent)}
                className="btn btn-secondary text-xs flex items-center gap-1.5"
              >
                <Copy size={13} />
                Copy JSON
              </button>
              <button
                onClick={() => setActiveModalEvent(null)}
                className="btn btn-primary text-xs"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LiveMonitoring;
