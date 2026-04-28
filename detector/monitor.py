"""
monitor.py — reads Nginx JSON log line by line, forever
"""
import json
import time
import os


class LogMonitor:
    def __init__(self, log_path):
        self.log_path = log_path
        self.callbacks = []

    def register(self, callback):
        self.callbacks.append(callback)

    def tail(self):
        print(f"[monitor] Waiting for log: {self.log_path}")
        while not os.path.exists(self.log_path):
            time.sleep(1)

        print("[monitor] Log found — tailing...")
        with open(self.log_path, "r") as f:
            f.seek(0, 2)  # start at end of file
            last_size = f.tell()

            while True:
                current_size = os.path.getsize(self.log_path)
                if current_size < last_size:
                    print("[monitor] Log rotated — reopening")
                    f.close()
                    f = open(self.log_path, "r")
                    last_size = 0

                line = f.readline()
                if not line:
                    time.sleep(0.05)
                    continue

                line = line.strip()
                if not line:
                    continue

                parsed = self._parse(line)
                if parsed:
                    for cb in self.callbacks:
                        cb(parsed)

                last_size = f.tell()

    def _parse(self, line):
        try:
            d = json.loads(line)
            return {
                "source_ip":     d.get("source_ip", "-").split(",")[0].strip(),
                "timestamp":     d.get("timestamp", ""),
                "method":        d.get("method", ""),
                "path":          d.get("path", ""),
                "status":        int(d.get("status", 0)),
                "response_size": int(d.get("response_size", 0)),
            }
        except Exception:
            return None
