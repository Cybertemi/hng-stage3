"""
detector.py — sliding window anomaly detection
"""
import time
import threading
from collections import deque, defaultdict


class AnomalyDetector:
    def __init__(self, config, baseline, on_ip_anomaly, on_global_anomaly):
        self.win_sec = config["sliding_window_seconds"]
        self.z_thresh = config["zscore_threshold"]
        self.rate_mult = config["rate_multiplier_threshold"]
        self.err_mult = config["error_rate_multiplier"]

        self.baseline = baseline
        self.on_ip_anomaly = on_ip_anomaly
        self.on_global_anomaly = on_global_anomaly

        self.ip_windows = defaultdict(deque)
        self.ip_err_windows = defaultdict(deque)
        self.global_window = deque()

        # Cooldown trackers — prevent alert spam
        self.flagged_ips = {}           # ip → last flagged time
        self.last_global_alert = 0      # last global alert time
        self.global_cooldown = 60       # seconds between global alerts

        self.lock = threading.Lock()

    def process(self, entry):
        ip = entry["source_ip"]
        ts = time.time()
        status = entry["status"]

        with self.lock:
            # Add to sliding windows
            self.ip_windows[ip].append(ts)
            self.global_window.append(ts)
            if status >= 400:
                self.ip_err_windows[ip].append(ts)

            # Evict expired entries
            self._evict(self.ip_windows[ip])
            self._evict(self.global_window)
            self._evict(self.ip_err_windows[ip])

            # Current rates
            ip_rate = len(self.ip_windows[ip])
            global_rate = len(self.global_window)
            err_rate = len(self.ip_err_windows[ip])

            # Only check anomalies if baseline has enough data
            if self.baseline.mean == 0:
                return

            # Tighten thresholds if error surge detected
            z_thresh = self.z_thresh
            r_mult = self.rate_mult
            if err_rate > self.baseline.mean * self.err_mult:
                z_thresh *= 0.7
                r_mult *= 0.7

            # ── Per-IP anomaly check ──────────────────────────
            ip_z = self.baseline.zscore(ip_rate)
            last_flagged = self.flagged_ips.get(ip, 0)

            # Only flag if not flagged in last 60 seconds
            if time.time() - last_flagged > 60:
                if (ip_z > z_thresh or
                        ip_rate > self.baseline.mean * r_mult):
                    self.flagged_ips[ip] = time.time()
                    condition = "zscore" if ip_z > z_thresh \
                        else "rate_multiplier"
                    self.on_ip_anomaly(
                        ip=ip,
                        rate=ip_rate,
                        zscore=ip_z,
                        baseline_mean=self.baseline.mean,
                        condition=condition,
                    )

            # ── Global anomaly check ──────────────────────────
            # Only alert once per cooldown period
            if time.time() - self.last_global_alert > self.global_cooldown:
                g_z = self.baseline.zscore(global_rate)
                if (g_z > z_thresh or
                        global_rate > self.baseline.mean * r_mult):
                    self.last_global_alert = time.time()
                    self.on_global_anomaly(
                        rate=global_rate,
                        zscore=g_z,
                        baseline_mean=self.baseline.mean,
                    )

    def _evict(self, window):
        cutoff = time.time() - self.win_sec
        while window and window[0] < cutoff:
            window.popleft()

    def get_top_ips(self, n=10):
        with self.lock:
            return sorted(
                [(ip, len(w)) for ip, w in self.ip_windows.items()],
                key=lambda x: x[1], reverse=True
            )[:n]

    def get_global_rate(self):
        with self.lock:
            self._evict(self.global_window)
            return len(self.global_window)
