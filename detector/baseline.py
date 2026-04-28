"""
baseline.py — rolling 30-minute mean and stddev of request rates
"""
import time
import math
import threading
from collections import deque


class BaselineTracker:
    def __init__(self, config):
        self.window_seconds = config["baseline_window_minutes"] * 60
        self.recalc_interval = config["baseline_recalc_interval"]
        self.min_samples = config["baseline_min_samples"]

        self.window = deque()   # (timestamp, count) per second
        self.lock = threading.Lock()

        self._cur_second = int(time.time())
        self._cur_count = 0

        self.mean = 0.0
        self.stddev = 1.0
        self.hourly_slots = {}

        threading.Thread(target=self._loop, daemon=True).start()

    def record(self):
        now = int(time.time())
        with self.lock:
            if now == self._cur_second:
                self._cur_count += 1
            else:
                self.window.append((self._cur_second, self._cur_count))
                self._cur_second = now
                self._cur_count = 1
            self._evict()

    def _evict(self):
        cutoff = time.time() - self.window_seconds
        while self.window and self.window[0][0] < cutoff:
            self.window.popleft()

    def _loop(self):
        while True:
            time.sleep(self.recalc_interval)
            self._recalc()

    def _recalc(self):
        with self.lock:
            self._evict()
            counts = [c for _, c in self.window]

        if len(counts) < self.min_samples:
            return

        mean = sum(counts) / len(counts)
        var = sum((c - mean) ** 2 for c in counts) / len(counts)
        stddev = math.sqrt(var) if var > 0 else 1.0

        hour = time.strftime("%Y-%m-%d-%H")
        self.hourly_slots[hour] = {"mean": mean, "stddev": stddev}

        self.mean = mean
        self.stddev = max(stddev, 1.0)
        print(f"[baseline] mean={self.mean:.2f} stddev={self.stddev:.2f} "
              f"n={len(counts)}")

    def zscore(self, rate):
        if self.stddev == 0:
            return 0.0
        return (rate - self.mean) / self.stddev

    def get_stats(self):
        return {
            "mean":         round(self.mean, 2),
            "stddev":       round(self.stddev, 2),
            "hourly_slots": len(self.hourly_slots),
        }
