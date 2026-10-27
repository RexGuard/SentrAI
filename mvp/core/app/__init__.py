"""SentrAI core service."""
import sys as _sys
from pathlib import Path as _Path

# mvp/, for sentrai_config, sentrai_paths and sentrai_llm (shared by every part)
_sys.path.append(str(_Path(__file__).resolve().parents[2]))

