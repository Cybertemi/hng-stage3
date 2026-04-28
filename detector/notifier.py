"""
notifier.py — Slack webhook alerts
"""
import requests
import time
import threading


class Notifier:
    def __init__(self, webhook_url):
        self.url = webhook_url

    def _send(self, text):
        def _post():
            try:
                requests.post(self.url,
                              json={"text": text}, timeout=10)
            except Exception as e:
                print(f"[notifier] Slack error: {e}")
        threading.Thread(target=_post, daemon=True).start()

    def ban(self, ip, rate, zscore, baseline_mean,
            condition, ban_count, duration):
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        self._send(
            f":red_circle: *IP BANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Condition:* {condition}\n"
            f"*Rate:* {rate} req/60s\n"
            f"*Baseline mean:* {baseline_mean:.2f}\n"
            f"*Z-score:* {zscore:.2f}\n"
            f"*Ban #{ban_count}* — Duration: {duration}s\n"
            f"*Time:* {ts}"
        )

    def unban(self, ip, ban_count):
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        self._send(
            f":white_check_mark: *IP UNBANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Total bans:* {ban_count}\n"
            f"*Time:* {ts}"
        )

    def global_anomaly(self, rate, zscore, baseline_mean):
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        self._send(
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"*Rate:* {rate} req/60s\n"
            f"*Baseline mean:* {baseline_mean:.2f}\n"
            f"*Z-score:* {zscore:.2f}\n"
            f"*Time:* {ts}"
        )
