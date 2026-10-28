import os
import sys
from pathlib import Path

os.environ["BNA_NO_AUTOSTART"] = "1"
os.environ.setdefault("LEDGER_SALT", "test-salt")
os.environ["ALLOWED_RECIPIENT_DOMAINS"] = "simulator.amazonses.com"
os.environ["SES_FROM"] = "agent@example.test"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
