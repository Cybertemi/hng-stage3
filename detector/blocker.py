"""
blocker.py — iptables ban/unban with backoff schedule
"""
import subprocess
import time
import threading


class Blocker:
    def __init__(self, config, on_ban, on_unban):
        self.schedule = config["unban_schedule"]
        self.on_ban = on_ban
        self.on_unban = on_unban
        self.banned = {}
        self.ban_counts = {}
        self.lock = threading.Lock()
        threading.Thread(target=self._unban_loop, daemon=True).start()

    def ban(self, ip, rate, zscore, baseline_mean, condition):
        with self.lock:
            if ip in self.banned:
                return

            count = self.ban_counts.get(ip, 0) + 1
            self.ban_counts[ip] = count

            if count - 1 < len(self.schedule):
                duration = self.schedule[count - 1]
                unban_at = time.time() + duration
            else:
                duration = "permanent"
                unban_at = None

            self.banned[ip] = {
                "count":     count,
                "banned_at": time.time(),
                "unban_at":  unban_at,
                "rate":      rate,
                "zscore":    zscore,
            }

        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            print(f"[blocker] BANNED {ip} count={count} "
                  f"duration={duration}")
        except subprocess.CalledProcessError as e:
            print(f"[blocker] iptables failed: {e.stderr.decode()}")

        self.on_ban(
            ip=ip, rate=rate, zscore=zscore,
            baseline_mean=baseline_mean, condition=condition,
            ban_count=count, duration=duration,
        )

    def unban(self, ip):
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
        except subprocess.CalledProcessError:
            pass

        with self.lock:
            info = self.banned.pop(ip, {})

        print(f"[blocker] UNBANNED {ip}")
        self.on_unban(ip=ip, ban_count=info.get("count", 0))

    def _unban_loop(self):
        while True:
            time.sleep(30)
            now = time.time()
            to_unban = []
            with self.lock:
                for ip, info in self.banned.items():
                    if info["unban_at"] and now >= info["unban_at"]:
                        to_unban.append(ip)
            for ip in to_unban:
                self.unban(ip)

    def get_banned(self):
        with self.lock:
            return dict(self.banned)
