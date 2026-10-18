import { useState } from 'react';
import { 
  Shield, Zap, AlertTriangle, CheckCircle, Code, Target, 
  Copy, Play, Terminal, ArrowRight, CornerDownRight, Server, RefreshCw
} from 'lucide-react';
import { wafApi, API_BASE_URL } from '../services/api';
import { useToast } from '../context/ToastContext';

interface SimulationResult {
  attack_type?: string;
  detection_result?: {
    anomaly_score: number;
    is_anomalous: boolean;
    threshold: number;
    reconstruction_error: number;
    perplexity: number;
    confidence?: number;
    latency_ms?: number;
  };
  anomaly_score?: number;
  is_anomalous?: boolean;
  threshold?: number;
  reconstruction_error?: number;
  perplexity?: number;
  timestamp: string;
}

const PRESET_ATTACKS = [
  {
    id: 'sql_injection',
    name: 'SQL Injection (SQLi)',
    category: 'OWASP A03:2021',
    description: 'Bypasses authentication logic via unescaped SQL quotation and boolean tautology.',
    defaultPath: '/api/users',
    example: "?id=1' OR '1'='1",
    method: 'GET',
    body: '',
    severity: 'critical',
    icon: Code,
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS)',
    category: 'OWASP A03:2021',
    description: 'Injects malicious JavaScript executable in client browser context.',
    defaultPath: '/search',
    example: '?search=<script>alert("WAF_TEST_XSS")</script>',
    method: 'GET',
    body: '',
    severity: 'high',
    icon: AlertTriangle,
  },
  {
    id: 'path_traversal',
    name: 'Path Traversal (LFI)',
    category: 'OWASP A01:2021',
    description: 'Attempts to traverse filesystem root to expose sensitive system configuration.',
    defaultPath: '/../../../etc/passwd',
    example: '',
    method: 'GET',
    body: '',
    severity: 'critical',
    icon: Target,
  },
  {
    id: 'command_injection',
    name: 'Command Injection (RCE)',
    category: 'OWASP A03:2021',
    description: 'Attempts to chain shell execution commands via semicolon delimiter.',
    defaultPath: '/api/system/diag',
    example: '',
    method: 'POST',
    body: 'cmd=ls; cat /etc/shadow',
    severity: 'critical',
    icon: Zap,
  },
];

const AttackSimulation = () => {
  const { success, error: toastError } = useToast();

  const [activeTab, setActiveTab] = useState<'preset' | 'custom'>('preset');
  const [selectedAttack, setSelectedAttack] = useState<string>('sql_injection');
  const [targetPath, setTargetPath] = useState<string>('/api/users');
  const [isSimulating, setIsSimulating] = useState(false);
  const [results, setResults] = useState<SimulationResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Custom request builder state
  const [customMethod, setCustomMethod] = useState<'GET' | 'POST' | 'PUT' | 'DELETE'>('GET');
  const [customPath, setCustomPath] = useState<string>('/api/orders');
  const [customQuery, setCustomQuery] = useState<string>('debug=true&filter=admin');
  const [customBody, setCustomBody] = useState<string>('{"role": "superuser"}');
  const [customHeaderKey, setCustomHeaderKey] = useState<string>('User-Agent');
  const [customHeaderVal, setCustomHeaderVal] = useState<string>('Nikto/2.5.0');

  const handlePresetChange = (attackId: string) => {
    setSelectedAttack(attackId);
    const found = PRESET_ATTACKS.find((a) => a.id === attackId);
    if (found) {
      setTargetPath(found.defaultPath);
    }
  };

  const handleSimulatePreset = async () => {
    if (!targetPath.trim()) {
      setError('Please specify a target path (e.g. /api/users)');
      return;
    }

    setIsSimulating(true);
    setError(null);

    try {
      const data = await wafApi.simulateAttack({
        attack_type: selectedAttack,
        target_path: targetPath,
      });

      setResults((prev) => [data, ...prev].slice(0, 20));
      success('Simulation Complete', `${selectedAttack} simulated against ${targetPath}`);
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || 'Simulation failed';
      setError(msg);
      toastError('Simulation Error', msg);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleSimulateCustom = async () => {
    if (!customPath.trim()) {
      setError('Please enter a target path (e.g. /api/endpoint)');
      return;
    }

    setIsSimulating(true);
    setError(null);

    try {
      const headers: Record<string, string> = {};
      if (customHeaderKey && customHeaderVal) {
        headers[customHeaderKey] = customHeaderVal;
      }

      const scanResult = await wafApi.scan({
        method: customMethod,
        path: customPath.startsWith('/') ? customPath : `/${customPath}`,
        query_string: customQuery,
        headers,
        body: customMethod !== 'GET' ? customBody : '',
      });

      const formattedResult: SimulationResult = {
        attack_type: 'custom_payload',
        detection_result: {
          anomaly_score: scanResult.anomaly_score,
          is_anomalous: scanResult.is_anomalous,
          threshold: scanResult.threshold,
          reconstruction_error: scanResult.reconstruction_error,
          perplexity: scanResult.perplexity,
          confidence: scanResult.confidence,
        },
        timestamp: scanResult.timestamp || new Date().toISOString(),
      };

      setResults((prev) => [formattedResult, ...prev].slice(0, 20));
      success('Custom Request Scanned', `Processed ${customMethod} ${customPath}`);
    } catch (err: any) {
      const msg = err.response?.data?.detail?.error || err.response?.data?.detail || err.message || 'Scan failed';
      setError(typeof msg === 'string' ? msg : JSON.stringify(msg));
      toastError('Scan Error', 'Unable to complete request scan');
    } finally {
      setIsSimulating(false);
    }
  };

  const copyCurl = () => {
    const selected = PRESET_ATTACKS.find((a) => a.id === selectedAttack);
    let curl = '';
    if (activeTab === 'preset' && selected) {
      const fullUrl = `${API_BASE_URL}/simulate/attack`;
      curl = `curl -X POST "${fullUrl}" -H "Content-Type: application/json" -d '{"attack_type": "${selected.id}", "target_path": "${targetPath}"}'`;
    } else {
      const fullUrl = `${API_BASE_URL}/scan`;
      curl = `curl -X POST "${fullUrl}" -H "Content-Type: application/json" -d '{"method": "${customMethod}", "path": "${customPath}", "query_string": "${customQuery}", "body": "${customBody.replace(/"/g, '\\"')}"}'`;
    }
    navigator.clipboard.writeText(curl);
    success('cURL Copied', 'cURL command copied to clipboard');
  };

  const selectedPreset = PRESET_ATTACKS.find((a) => a.id === selectedAttack);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-white">
              Attack Simulation Lab
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 dark:bg-rose-950/60 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-900/50">
              <Zap size={13} />
              Interactive Tester
            </span>
          </div>
          <p className="text-slate-600 dark:text-slate-400 text-sm mt-1">
            Evaluate DistilBERT detection accuracy against OWASP Top 10 attack payloads and custom test cases
          </p>
        </div>

        {/* Tab switch button */}
        <div className="flex p-1 rounded-xl bg-slate-100 dark:bg-dark-800 border border-slate-200/80 dark:border-dark-700/80 text-xs">
          <button
            onClick={() => { setActiveTab('preset'); setError(null); }}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
              activeTab === 'preset'
                ? 'bg-white dark:bg-dark-700 text-slate-900 dark:text-white shadow-xs'
                : 'text-slate-500 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Preset Attacks
          </button>
          <button
            onClick={() => { setActiveTab('custom'); setError(null); }}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
              activeTab === 'custom'
                ? 'bg-white dark:bg-dark-700 text-slate-900 dark:text-white shadow-xs'
                : 'text-slate-500 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Custom Request Builder
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-900/50 text-rose-700 dark:text-rose-300 rounded-xl text-xs flex items-center gap-2">
          <AlertTriangle size={16} className="flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Interaction Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Columns: Config & Launcher */}
        <div className="card lg:col-span-2 space-y-5">
          {activeTab === 'preset' ? (
            <>
              {/* Preset Cards Selection */}
              <div>
                <label className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-2.5">
                  Select Attack Vector
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {PRESET_ATTACKS.map((atk) => {
                    const isSelected = selectedAttack === atk.id;
                    const Icon = atk.icon;
                    return (
                      <div
                        key={atk.id}
                        onClick={() => handlePresetChange(atk.id)}
                        className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                          isSelected
                            ? 'bg-primary-50/70 dark:bg-primary-950/30 border-primary-500 ring-1 ring-primary-500'
                            : 'bg-slate-50/60 dark:bg-dark-800/60 border-slate-200 dark:border-dark-700 hover:border-slate-300 dark:hover:border-dark-600'
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <div className={`p-2 rounded-lg ${
                            atk.severity === 'critical'
                              ? 'bg-rose-500/10 text-rose-500'
                              : 'bg-amber-500/10 text-amber-500'
                          }`}>
                            <Icon size={18} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-bold text-slate-900 dark:text-white truncate">
                                {atk.name}
                              </span>
                              <span className="text-[10px] uppercase font-bold text-slate-400">
                                {atk.category}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 line-clamp-2">
                              {atk.description}
                            </p>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Target Endpoint Input */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block">
                  Target Endpoint Path
                </label>
                <div className="flex items-center gap-2">
                  <span className="px-3 py-2 rounded-lg bg-slate-100 dark:bg-dark-800 text-slate-500 font-mono text-xs border border-slate-200 dark:border-dark-700">
                    {selectedPreset?.method}
                  </span>
                  <input
                    type="text"
                    value={targetPath}
                    onChange={(e) => setTargetPath(e.target.value)}
                    placeholder="/api/users"
                    className="input-field font-mono text-xs"
                  />
                </div>
              </div>

              {/* Payload Preview */}
              {selectedPreset?.example && (
                <div className="p-3 bg-slate-900 text-slate-100 dark:bg-dark-950 rounded-xl font-mono text-xs border border-slate-800">
                  <span className="text-slate-400 text-[10px] uppercase block mb-1">Simulated Query String</span>
                  <code className="text-emerald-400 break-all">{selectedPreset.example}</code>
                </div>
              )}
            </>
          ) : (
            <>
              {/* Custom Request Builder Form */}
              <div className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1">
                      HTTP Method
                    </label>
                    <select
                      value={customMethod}
                      onChange={(e: any) => setCustomMethod(e.target.value)}
                      className="input-field text-xs font-mono font-bold"
                    >
                      <option value="GET">GET</option>
                      <option value="POST">POST</option>
                      <option value="PUT">PUT</option>
                      <option value="DELETE">DELETE</option>
                    </select>
                  </div>

                  <div className="sm:col-span-2">
                    <label className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1">
                      Endpoint Path
                    </label>
                    <input
                      type="text"
                      value={customPath}
                      onChange={(e) => setCustomPath(e.target.value)}
                      placeholder="/api/auth/login"
                      className="input-field font-mono text-xs"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1">
                    Query String (Optional)
                  </label>
                  <input
                    type="text"
                    value={customQuery}
                    onChange={(e) => setCustomQuery(e.target.value)}
                    placeholder="id=1&type=admin"
                    className="input-field font-mono text-xs"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1">
                      Header Key
                    </label>
                    <input
                      type="text"
                      value={customHeaderKey}
                      onChange={(e) => setCustomHeaderKey(e.target.value)}
                      placeholder="User-Agent"
                      className="input-field font-mono text-xs"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1">
                      Header Value
                    </label>
                    <input
                      type="text"
                      value={customHeaderVal}
                      onChange={(e) => setCustomHeaderVal(e.target.value)}
                      placeholder="CustomBot/1.0"
                      className="input-field font-mono text-xs"
                    />
                  </div>
                </div>

                {customMethod !== 'GET' && (
                  <div>
                    <label className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1">
                      Request Body (JSON / Form)
                    </label>
                    <textarea
                      rows={3}
                      value={customBody}
                      onChange={(e) => setCustomBody(e.target.value)}
                      placeholder='{"username": "admin"}'
                      className="input-field font-mono text-xs"
                    />
                  </div>
                )}
              </div>
            </>
          )}

          {/* Action buttons */}
          <div className="pt-3 border-t border-slate-200 dark:border-dark-700/80 flex items-center justify-between">
            <button
              onClick={copyCurl}
              className="btn btn-secondary text-xs flex items-center gap-1.5"
            >
              <Terminal size={14} />
              Copy cURL
            </button>

            <button
              onClick={activeTab === 'preset' ? handleSimulatePreset : handleSimulateCustom}
              disabled={isSimulating}
              className="btn btn-primary text-xs flex items-center gap-2 px-5 py-2.5"
            >
              {isSimulating ? (
                <>
                  <RefreshCw size={15} className="animate-spin" />
                  <span>Inferencing DistilBERT...</span>
                </>
              ) : (
                <>
                  <Play size={15} />
                  <span>Launch Attack Simulation</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right 1 Column: Attack Details & Overview */}
        <div className="card space-y-4">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-primary-500/10 text-primary-500">
              <Shield size={20} />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">ML Inference Pipeline</h3>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">Zero-Day Detection Logic</p>
            </div>
          </div>

          <div className="space-y-3 text-xs text-slate-600 dark:text-slate-400">
            <div className="p-3 rounded-xl bg-slate-50 dark:bg-dark-800/80 border border-slate-200/80 dark:border-dark-700/80">
              <span className="font-bold text-slate-900 dark:text-white block mb-1">1. Normalization & Masking</span>
              <span>De-hex, URI unquoting, parameter parsing, and sensitive token stripping.</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-50 dark:bg-dark-800/80 border border-slate-200/80 dark:border-dark-700/80">
              <span className="font-bold text-slate-900 dark:text-white block mb-1">2. DistilBERT Attention</span>
              <span>Calculates token perplexity and reconstruction loss across 6 transformer layers.</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-50 dark:bg-dark-800/80 border border-slate-200/80 dark:border-dark-700/80">
              <span className="font-bold text-slate-900 dark:text-white block mb-1">3. Decision Enforcement</span>
              <span>Compares anomaly score against configured threshold to allow or reject request.</span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-900/40 text-[11px] text-amber-800 dark:text-amber-300">
            <strong>Demonstration Tip:</strong> Try attacking with both classic SQLi statements and normal benign paths (e.g. <code className="font-mono">/api/users/profile</code>) to witness the contrast in anomaly scores.
          </div>
        </div>
      </div>

      {/* Simulation Results History */}
      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white">
              Simulation Results History
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Real-time feedback directly from the WAF evaluation engine
            </p>
          </div>
          {results.length > 0 && (
            <button
              onClick={() => setResults([])}
              className="text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              Clear Results
            </button>
          )}
        </div>

        {results.length === 0 ? (
          <div className="text-center py-10 border border-dashed border-slate-200 dark:border-dark-700 rounded-xl">
            <Zap className="w-10 h-10 text-slate-300 dark:text-dark-700 mx-auto mb-2" />
            <p className="text-sm font-semibold text-slate-700 dark:text-slate-300">No simulations executed yet</p>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Click "Launch Attack Simulation" above to trigger a test</p>
          </div>
        ) : (
          <div className="space-y-3">
            {results.map((res, idx) => {
              const detection = res.detection_result || res;
              const score = detection.anomaly_score ?? 0;
              const isBlocked = detection.is_anomalous ?? false;
              const threshold = detection.threshold ?? 0.75;

              return (
                <div
                  key={idx}
                  className={`p-4 rounded-xl border transition-all ${
                    isBlocked
                      ? 'bg-rose-50/40 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/50'
                      : 'bg-emerald-50/40 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-900/50'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
                    <div className="flex items-center gap-2">
                      <span className={`px-2.5 py-1 rounded-lg text-xs font-bold uppercase ${
                        isBlocked
                          ? 'bg-rose-600 text-white'
                          : 'bg-emerald-600 text-white'
                      }`}>
                        {isBlocked ? '🚨 Anomaly Detected' : '✓ Normal Traffic'}
                      </span>
                      <span className="font-mono text-xs font-bold text-slate-900 dark:text-white">
                        {res.attack_type?.toUpperCase() || 'CUSTOM'}
                      </span>
                    </div>
                    <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                      {new Date(res.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  {/* Score Meter & Metrics */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-center">
                    <div className="md:col-span-2">
                      <div className="flex justify-between text-xs font-semibold mb-1">
                        <span className="text-slate-500 dark:text-slate-400">Anomaly Score</span>
                        <span className={`font-mono font-bold ${
                          score > threshold ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'
                        }`}>
                          {score.toFixed(4)} / 1.0000
                        </span>
                      </div>
                      <div className="h-2.5 rounded-full bg-slate-200 dark:bg-dark-700 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            score > threshold ? 'bg-rose-500' : 'bg-emerald-500'
                          }`}
                          style={{ width: `${Math.min(score * 100, 100)}%` }}
                        />
                      </div>
                      <span className="text-[10px] text-slate-400 mt-1 block">Threshold: {threshold}</span>
                    </div>

                    <div className="p-2 rounded-lg bg-white/80 dark:bg-dark-900/80 border border-slate-200/60 dark:border-dark-700/60 text-center">
                      <span className="text-[10px] text-slate-400 uppercase font-semibold block">Reconstruction Err</span>
                      <span className="text-xs font-bold text-slate-900 dark:text-white font-mono mt-0.5 block">
                        {(detection.reconstruction_error ?? 0).toFixed(4)}
                      </span>
                    </div>

                    <div className="p-2 rounded-lg bg-white/80 dark:bg-dark-900/80 border border-slate-200/60 dark:border-dark-700/60 text-center">
                      <span className="text-[10px] text-slate-400 uppercase font-semibold block">Perplexity</span>
                      <span className="text-xs font-bold text-slate-900 dark:text-white font-mono mt-0.5 block">
                        {(detection.perplexity ?? 0).toFixed(1)}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default AttackSimulation;
