"""Run every attack scenario against the registered camera, ONE BY ONE.

Fires each scenario (via inject_camera.py) for `dur` seconds, then pauses `pause`
seconds before the next, so each class shows up separately on the Home Network
dashboard and you can confirm the model's prediction one at a time.

Usage:
  python run_all.py [dur] [pause] [backend_url] [count]

Defaults: dur=60, pause=20, backend_url=http://localhost:8000, count=25
Env: SCENARIOS="iotdos iotddos ..." to override/subset the list and order.
Stop early with Ctrl+C.
"""
import os
import sys
import time
import subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))
INJECTOR = os.path.join(_HERE, "inject_camera.py")

DEFAULT_SCENARIOS = [
    "iotdos", "iotddos", "iotslowloris", "iotbruteforce", "iotmitm",
    "iotevasion", "iotc2beac", "iotexfil", "iottlsssl",
]


def main():
    dur = sys.argv[1] if len(sys.argv) > 1 else "60"
    pause = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    backend = sys.argv[3] if len(sys.argv) > 3 else "http://localhost:8000"
    count = sys.argv[4] if len(sys.argv) > 4 else "25"

    scenarios = os.environ.get("SCENARIOS", " ".join(DEFAULT_SCENARIOS)).split()
    print("=== Sequential camera attack test: %d scenarios, %ss each, %ss pause ==="
          % (len(scenarios), dur, pause))
    for i, sc in enumerate(scenarios, 1):
        print("\n" + "=" * 70)
        print("[%d/%d] ATTACK: %s  (watch the dashboard / consumer now)" % (i, len(scenarios), sc))
        print("=" * 70)
        rc = subprocess.call([sys.executable, INJECTOR, sc, count, dur, backend])
        if rc != 0:
            print("  ! %s exited with code %d (stopping). Fix and re-run." % (sc, rc))
            return rc
        if i < len(scenarios):
            print("--- pausing %ss before next attack ---" % pause)
            try:
                time.sleep(pause)
            except KeyboardInterrupt:
                print("stopped by user")
                return 0
    print("\n=== all scenarios done ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
