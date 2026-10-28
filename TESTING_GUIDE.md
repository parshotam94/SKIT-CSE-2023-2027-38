
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
