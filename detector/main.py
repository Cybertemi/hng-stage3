"""
main.py — wires all components and starts the daemon
"""
import yaml
import threading

from monitor import LogMonitor
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from notifier import Notifier
from audit import AuditLogger
import dashboard


def load_config():
    with open("/app/config.yaml") as f:
        return yaml.safe_load(f)


def main():
    print("[main] HNG Anomaly Detector starting...")
    cfg = load_config()

    audit = AuditLogger(cfg["paths"]["audit_log"])
    notifier = Notifier(cfg["slack"]["webhook_url"])
    baseline = BaselineTracker(cfg)

    def on_ban(ip, rate, zscore, baseline_mean,
               condition, ban_count, duration):
        audit.log("BAN", ip=ip, condition=condition,
                  rate=rate, baseline=f"{baseline_mean:.2f}",
                  duration=duration)
        notifier.ban(ip=ip, rate=rate, zscore=zscore,
                     baseline_mean=baseline_mean, condition=condition,
                     ban_count=ban_count, duration=duration)

    def on_unban(ip, ban_count):
        audit.log("UNBAN", ip=ip)
        notifier.unban(ip=ip, ban_count=ban_count)

    def on_global(rate, zscore, baseline_mean):
        audit.log("GLOBAL_ANOMALY", rate=rate,
                  baseline=f"{baseline_mean:.2f}")
        notifier.global_anomaly(rate=rate, zscore=zscore,
                                baseline_mean=baseline_mean)

    blocker = Blocker(cfg, on_ban=on_ban, on_unban=on_unban)

    def on_ip_anomaly(ip, rate, zscore, baseline_mean, condition):
        blocker.ban(ip=ip, rate=rate, zscore=zscore,
                    baseline_mean=baseline_mean, condition=condition)

    detector = AnomalyDetector(
        config=cfg,
        baseline=baseline,
        on_ip_anomaly=on_ip_anomaly,
        on_global_anomaly=on_global,
    )

    monitor = LogMonitor(cfg["paths"]["nginx_log"])

    def handle(entry):
        baseline.record()
        detector.process(entry)

    monitor.register(handle)

    # Start dashboard in background
    port = cfg["dashboard"]["port"]
    threading.Thread(
        target=dashboard.start,
        args=(detector, baseline, blocker, port),
        daemon=True
    ).start()
    print(f"[main] Dashboard → http://0.0.0.0:{port}")

    # Start log monitor — runs forever
    monitor.tail()


if __name__ == "__main__":
    main()
