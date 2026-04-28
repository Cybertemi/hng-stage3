"""
audit.py — structured audit log
Format: [timestamp] ACTION ip | condition | rate | baseline | duration
"""
import time
import os


class AuditLogger:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path

    def log(self, action, ip="-", condition="-",
            rate="-", baseline="-", duration="-"):
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        line = (f"[{ts}] {action} {ip} | {condition} | "
                f"{rate} | {baseline} | {duration}")
        print(f"[audit] {line}")
        try:
            with open(self.path, "a") as f:
                f.write(line + "\n")
        except Exception as e:
            print(f"[audit] Write error: {e}")
