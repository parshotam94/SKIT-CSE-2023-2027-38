
# 🧪 Testing Guide - System Configuration & Demo Mode

## Quick Start Testing

### Prerequisites
- Backend running on http://localhost:8000
- Frontend running on http://localhost:5173
- Browser with DevTools open (F12)

---

## Test Scenarios

### Test 1: Demo Mode - 100 Requests

**Steps:**
1. Navigate to Settings page.
2. Toggle Demo Mode ON.
3. Click Save Configuration.
4. Watch the progress bar fill up.
5. Verify counter updates: 0/100 → 25/100 → 50/100 → 75/100 → 100/100.
6. Confirm "Demo Complete!" message appears.
7. Verify demo mode auto-disables.

**Expected Results:**
- Progress bar animates smoothly.
- Counter updates every ~2 seconds.
- Backend generates exactly 100 requests.
- Demo auto-stops at 100/100.
- Dashboard shows demo counter badge.
- Live Monitoring shows traffic.
- Analytics shows real data (not demo data).

**Console Logs (Backend):**
```text
INFO: Demo progress: 25/100 requests
INFO: Demo progress: 50/100 requests
INFO: Demo progress: 75/100 requests
INFO: Demo progress: 100/100 requests
INFO: Demo mode complete: 100 requests generated
```

---

### Test 2: Demo Reset Button

**Steps:**
1. After demo completes (100/100).
2. Click Reset & Restart button.
3. Verify counter resets to 0/100.
4. Verify demo mode re-enables.
5. Watch new 100 requests generate.

**Expected Results:**
- Counter resets instantly.
- Progress bar starts from 0%.
- New traffic appears in Live Monitoring.
- Analytics updates with new events.

---

### Test 4: Anomaly Threshold Sync

**Steps:**
1. Settings → Anomaly Threshold: 0.3 (Low).
2. Save Configuration.
3. Send borderline request (score ~0.4).
4. Verify detection: Anomalous (0.4 > 0.3).
5. Settings → Anomaly Threshold: 0.7 (High).
6. Save Configuration.
7. Send same request again.
8. Verify detection: Normal (0.4 < 0.7).

**Expected Results:**
- Threshold updates globally.
- Detector uses new threshold immediately.
- Live Monitoring shows different results.
- Analytics reflects new classification.


### Test 3: Detection Modes

#### Monitor Mode

**Steps:**
1. Settings → Detection Mode: Monitor Only.
2. Save Configuration.
3. Send anomalous request (manual or wait for demo).
4. Check backend logs.

**Expected Results:**
- Request logged only.
- No alerts or blocks.
- HTTP 200 response.
- Dashboard badge shows "👁️ Monitor Only" (blue).

#### Detect & Alert Mode

**Steps:**
1. Settings → Detection Mode: Detect & Alert.
2. Save Configuration.
3. Send anomalous request.
4. Check backend logs.

**Expected Results:**
- Request logged with WARNING level.
- Alert message: "Anomalous request detected (allowed)".
- HTTP 200 response (request allowed).
- Dashboard badge shows "⚠️ Detect & Alert" (yellow).

#### Block Mode

**Steps:**
1. Settings → Detection Mode: Block Mode.
2. Save Configuration.
3. Send anomalous request.
4. Check response.

**Expected Results:**
- Request rejected with HTTP 403.
- Error response:

```json
{
  "detail": {
    "error": "Request blocked by WAF",
    "reason": "Anomalous request detected",
    "severity": "High",
    "anomaly_score": 0.87
  }
}
```

- Dashboard badge shows "🛡️ Block Mode" (red).

**Test Request (curl):**

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "path": "/api/users",
    "query_string": "id=1 OR 1=1",
    "headers": {"User-Agent": "sqlmap"},
    "body": ""
  }'
```

---

### Test 5: Dashboard Real-Time Sync

**Steps:**
1. Open Dashboard page.
2. Enable demo mode in Settings (separate tab).
3. Watch Dashboard header.
4. Verify badges update:
   - Demo counter: "🎮 Demo: 25/100"
   - Detection mode badge.
   - Health status badge.
5. Change detection mode in Settings.
6. Refresh Dashboard (or wait 5s).
7. Verify mode badge updates.

**Expected Results:**
- Dashboard auto-refreshes every 5s.
- Demo counter updates in real time.
- Mode badges show correct colors.
- Settings icon link works.

---

### Test 6: Analytics Live Data

**Steps:**
1. Navigate to Analytics page.
2. Verify "Demo Data (No Traffic Yet)" badge (if no traffic).
3. Enable demo mode.
4. Wait 5 seconds.
5. Verify badge changes to "● Live Data" (green, pulsing).
6. Verify charts populate with real data.
7. Verify detection mode badge appears.

**Expected Results:**
- Data source badge updates correctly.
- Charts show real demo traffic.
- Hourly trend updates.
- Attack distribution shows actual patterns.
- Severity distribution reflects real scores.

---

### Test 7: Live Monitoring WebSocket

**Steps:**
1. Navigate to Live Monitoring page.
2. Verify connection status: "WebSocket Connected" (green).
3. Enable demo mode in Settings.
4. Watch events stream in real time.
5. Verify event details:
   - Path, method, query.
   - Anomaly score.
   - Severity badge (color-coded).
   - Timestamp.

**Expected Results:**
- WebSocket connects immediately.
- Events appear within 2 seconds.
- Max 100 events displayed.
- Stats update (total, anomalous, average score).
- Auto-reconnects if disconnected.


### Test 8: UI/UX Animations

**Steps:**
1. Settings page:
   - Hover over buttons → Scale up (105%).
   - Click buttons → Scale down (95%).
   - Save button shows spinner during save.
2. Demo progress bar:
   - Animates smoothly (500ms transition).
   - Gradient colors.
3. Badges:
   - "Live Data" badge pulses.
   - Mode badges color-coded.
4. Cards:
   - Hover → Shadow increases.
   - Fade-in animation on load.

**Expected Results:**
- Smooth, professional animations.
- No janky transitions.
- Clear visual feedback.
- Accessible color contrasts.

---

## Troubleshooting

### Demo Not Generating Traffic

**Check:**
1. Backend logs: `INFO: Demo progress: X/100`.
2. `SYSTEM_CONFIG.demo_mode = True`.
3. Browser console for errors.
4. WebSocket connection status.

**Fix:**
- Restart backend: `Ctrl+C` then `python api/waf_api.py`.
- Clear browser cache.
- Check API endpoint: `GET http://localhost:8000/config`.

### Detection Mode Not Blocking

**Check:**
1. Config saved: `POST /config` returned 200.
2. Mode badge shows "Block" on Dashboard.
3. Request actually anomalous (score > threshold).

**Fix:**
- Re-save configuration.
- Check threshold setting (if too high, nothing blocks).
- Verify request is malicious (e.g., SQL injection).

### Progress Bar Not Updating

**Check:**
1. Browser console for errors.
2. Auto-refresh enabled (check useEffect).
3. Config endpoint returning demo_request_count.

**Fix:**
- Hard refresh (Ctrl+Shift+R).
- Check Network tab: `GET /config` every 2s.
- Verify backend incrementing counter.

---

## Success Criteria

- Demo generates exactly 100 requests.
- Demo auto-stops at 100/100.
- Progress bar updates smoothly.
- Reset button works.
- Monitor mode: logs only.
- Detect mode: alerts + allows.
- Block mode: rejects with 403.
- Threshold sync works globally.
- Dashboard shows real-time status.
- Analytics shows live data.
- Live Monitoring streams events.
- Animations are smooth.
- No console errors.
- No backend exceptions.

---

## Performance Benchmarks

### Demo Mode
- 100 requests @ 2s intervals = ~3.3 minutes.
- CPU usage: < 10%.
- Memory: < 100MB increase.

### Auto-Refresh
- Settings: Every 2s (during demo only).
- Dashboard: Every 5s.
- Analytics: Every 5s.
- Network overhead: < 1KB per request.

### WebSocket
- Latency: < 50ms.
- Bandwidth: ~5KB per event.
- Reconnect: < 3 seconds.

---

## Final Validation

**Test 1: Get config**
```bash
curl http://localhost:8000/config
```

**Test 2: Enable demo mode**
```bash
curl -X POST http://localhost:8000/config \
  -H "Content-Type: application/json" \
  -d '{
    "anomaly_threshold": 0.5,
    "detection_mode": "detect",
    "demo_mode": true,
    "demo_request_count": 0,
    "demo_total_requests": 100,
    "severity_thresholds": {
      "low": 0.3,
      "medium": 0.6,
      "high": 0.85,
      "critical": 0.95
    },
    "logging_level": "info",
    "enable_notifications": true
  }'
```

**Test 3: Wait 30 seconds, then check progress**
```bash
sleep 30
curl http://localhost:8000/config | grep demo_request_count
```

**Test 4: Reset demo**
```bash
curl -X POST http://localhost:8000/config/reset-demo
```

**Test 5: Test block mode**
```bash
curl -X POST http://localhost:8000/config \
  -H "Content-Type: application/json" \
  -d '{"detection_mode": "block", ...}'
```

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "path": "/api/users",
    "query_string": "id=1 OR 1=1",
    "headers": {"User-Agent": "sqlmap"},
    "body": ""
  }'
```

Expected result: 403 Forbidden.

---

**Happy Testing! 🚀**

*Last Updated: February 3, 2026*
