import { useState, useEffect } from 'react'; 
import axios from 'axios';
import { Save, RefreshCw, Shield, Sliders, Bell, Code } from 'lucide-react';

const API_BASE_URL = 'http://localhost:8000';

interface SystemConfig {
  anomaly_threshold: number;
  detection_mode: 'monitor' | 'detect' | 'block';
  protected_app_url: string;
  demo_mode: boolean;
  demo_request_count: number;
  demo_total_requests: number;
  severity_thresholds: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  logging_level: 'debug' | 'info' | 'warning' | 'error';
  enable_notifications: boolean;
}

const DEFAULT_CONFIG: SystemConfig = {
  anomaly_threshold: 0.5,
  detection_mode: 'detect',
  protected_app_url: '',
  demo_mode: false,
  demo_request_count: 0,
  demo_total_requests: 100,
  severity_thresholds: {
    low: 0.3,
    medium: 0.6,
    high: 0.85,
    critical: 0.95
  },
  logging_level: 'info',
  enable_notifications: true
};

const normalizeConfig = (data: Partial<SystemConfig> | null | undefined): SystemConfig => {
  return {
    ...DEFAULT_CONFIG,
    ...(data || {}),
    severity_thresholds: {
      ...DEFAULT_CONFIG.severity_thresholds,
      ...((data && data.severity_thresholds) || {})
    }
  };
};

const Settings = () => {
  const [config, setConfig] = useState<SystemConfig>(DEFAULT_CONFIG);

  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    fetchConfig();

    // Auto-refresh config every 2 seconds when demo mode is active
    const interval = setInterval(() => {
      if (config.demo_mode && config.demo_request_count < config.demo_total_requests) {
        fetchConfig();
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [config.demo_mode, config.demo_request_count, config.demo_total_requests]);

  const fetchConfig = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/config`);
      setConfig(normalizeConfig(response.data));
    } catch (error) {
      console.error('Failed to fetch config:', error);
      // Use defaults if backend not ready
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveMessage(null);

    try {
      await axios.post(`${API_BASE_URL}/config`, config);
      setSaveMessage({ type: 'success', text: 'Configuration saved successfully!' });

      // Also update threshold via existing endpoint
      await axios.post(`${API_BASE_URL}/threshold?threshold=${config.anomaly_threshold}`);
    } catch (error: any) {
      setSaveMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || 'Failed to save configuration' 
      });
    } finally {
      setSaving(false);
      setTimeout(() => setSaveMessage(null), 5000);
    }
  };

  const handleDemoToggle = async (enabled: boolean) => {
    // Update local state immediately for responsive UI
    const updatedConfig = { ...config, demo_mode: enabled };
    setConfig(updatedConfig);

    // Save to backend immediately
    try {
      await axios.post(`${API_BASE_URL}/config`, updatedConfig);
      setSaveMessage({ 
        type: 'success', 
        text: enabled ? 'Demo mode enabled! Generating 100 requests...' : 'Demo mode disabled' 
      });
      setTimeout(() => setSaveMessage(null), 3000);
    } catch (error: any) {
      setSaveMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || 'Failed to update demo mode' 
      });
      // Revert local state on error
      setConfig(config);
      setTimeout(() => setSaveMessage(null), 5000);
    }
  };

  const handleReset = () => {
    setConfig(DEFAULT_CONFIG);
    setSaveMessage({ type: 'success', text: 'Configuration reset to defaults' });
    setTimeout(() => setSaveMessage(null), 3000);
  };

  const handleResetDemo = async () => {
    try {
      await axios.post(`${API_BASE_URL}/config/reset-demo`);
      await fetchConfig(); // Refresh config
      setSaveMessage({ type: 'success', text: 'Demo mode reset! Generating 100 new requests...' });
      setTimeout(() => setSaveMessage(null), 5000);
    } catch (error: any) {
      setSaveMessage({ 
        type: 'error', 
        text: error.response?.data?.detail || 'Failed to reset demo mode' 
      });
      setTimeout(() => setSaveMessage(null), 5000);
    }
  };