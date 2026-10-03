"""Optional always-on edge worker for prompt retries and timer recovery."""
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dotenv import load_dotenv
load_dotenv()
from src.pwa.api import transition
from src.pwa.alerts import drain_outbox

if __name__ == "__main__":
    while True:
        try:
            transition()
            drain_outbox()
        except Exception:
            print("Worker retry pending: check cloud connectivity/configuration.")
        time.sleep(1)
