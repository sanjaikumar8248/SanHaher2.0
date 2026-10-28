"""Resolves where SanHasher reads its bundled resources from, and where it
writes its data (database, uploaded evidence, cases, reports, wordlists).

Running normally (``python app.py``) these are the same place: the project
folder. Running as a PyInstaller-frozen desktop app they must NOT be the same
place — PyInstaller's ``--onefile`` mode extracts the bundle into a fresh
temp directory (``sys._MEIPASS``) on every launch and throws it away on
exit, so writing the database or evidence there would silently lose
everything the moment the app closes. In that case data goes to a normal,
persistent, per-user application-data folder instead, while templates/
static assets are still read from the (read-only) bundle.
"""
import os
import sys
from pathlib import Path


def resource_base() -> Path:
    """Where bundled, read-only assets (templates, static) live."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return Path(__file__).resolve().parent.parent


def data_base() -> Path:
    """Where the app writes its database, uploaded evidence, cases, reports, wordlists."""
    if getattr(sys, "frozen", False):
        if sys.platform == "win32":
            root = Path(os.environ.get("APPDATA", Path.home()))
        elif sys.platform == "darwin":
            root = Path.home() / "Library" / "Application Support"
        else:
            root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        base = root / "SanHasher2"
    else:
        base = Path(__file__).resolve().parent.parent
    base.mkdir(parents=True, exist_ok=True)
    return base
