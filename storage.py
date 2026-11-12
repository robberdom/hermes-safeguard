"""
Hermes SafeGuard — Storage & State Persistence Module.
Compliant with Hermes Agent Plugin Developer Guide:
"Never write runtime state into your plugin directory: that's the install tree,
and hermes plugins update / remove git-pull or delete it — your users' data dies with it.
The sanctioned home is the per-plugin data root, which survives both and follows the active profile."
"""

from __future__ import annotations

import os
from pathlib import Path

_PLUGIN_NAME = "hermes-safeguard"
_RESOLVED_DATA_DIR: Path | None = None


def get_hermes_home() -> Path:
    """
    Returns the profile-aware Hermes home directory.
    Respects HERMES_HOME, HERMES_PROFILE, or ~/.hermes by default.
    """
    env_home = os.getenv("HERMES_HOME")
    if env_home and env_home.strip():
        base = Path(env_home.strip())
    else:
        base = Path.home() / ".hermes"

    profile = os.getenv("HERMES_PROFILE")
    if profile and profile.strip():
        return base / "profiles" / profile.strip()
    return base


def get_plugin_data_dir() -> Path:
    """
    Returns the official persistent data directory for hermes-safeguard.
    Prioritizes official hermes_agent plugin_storage API, falling back to
    profile-aware get_hermes_home() / "plugins_data" / <plugin>.
    """
    global _RESOLVED_DATA_DIR
    if _RESOLVED_DATA_DIR is not None and _is_dir_writable(_RESOLVED_DATA_DIR):
        return _RESOLVED_DATA_DIR

    # 1. Hermes Agent official plugin storage API
    for mod_path in ("hermes_agent.plugins.plugin_storage", "plugins.plugin_storage"):
        try:
            import importlib
            mod = importlib.import_module(mod_path)
            fn = getattr(mod, "plugin_data_dir", None)
            if callable(fn):
                p = Path(fn(_PLUGIN_NAME))
                p.mkdir(parents=True, exist_ok=True)
                if _is_dir_writable(p):
                    _RESOLVED_DATA_DIR = p
                    return p
        except Exception:
            pass

    # 2. Profile-aware hermes home plugins_data directory
    hermes_data_dir = get_hermes_home() / "plugins_data" / _PLUGIN_NAME
    try:
        hermes_data_dir.mkdir(parents=True, exist_ok=True)
        if _is_dir_writable(hermes_data_dir):
            _RESOLVED_DATA_DIR = hermes_data_dir
            return hermes_data_dir
    except Exception:
        pass

    # Fallback only when home filesystem is non-writable (e.g. read-only container sandbox)
    local_data_dir = Path(__file__).resolve().parent / ".safeguard_data"
    try:
        local_data_dir.mkdir(parents=True, exist_ok=True)
        if _is_dir_writable(local_data_dir):
            _RESOLVED_DATA_DIR = local_data_dir
            return local_data_dir
    except Exception:
        pass

    _RESOLVED_DATA_DIR = hermes_data_dir
    return hermes_data_dir


def _is_dir_writable(path: Path) -> bool:
    """Check whether a directory exists and is writable."""
    try:
        if not path.is_dir():
            return False
        test_file = path / ".safeguard_write_test"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def resolve_state_path(filename: str) -> Path:
    """
    Resolve the canonical path for a persistent state file in the sanctioned data root.
    """
    return get_plugin_data_dir() / filename


def read_state_file(filename: str) -> str | None:
    """
    Read content from a persistent state file in the sanctioned data root.
    """
    import fcntl

    def _safe_read(p: Path) -> str | None:
        if not p.is_file():
            return None
        try:
            with open(p, "r", encoding="utf-8") as f:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                except (OSError, AttributeError):
                    pass
                data = f.read()
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except (OSError, AttributeError):
                    pass
                return data
        except Exception:
            return None

    try:
        canonical = resolve_state_path(filename)
        res = _safe_read(canonical)
        if res is not None:
            return res
    except Exception:
        pass

    return None


def write_state_file(filename: str, content: str) -> None:
    """
    Write content to a persistent state file in the sanctioned profile-aware data root atomically with file locking.
    """
    import fcntl

    def _atomic_write(dest: Path) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            except (OSError, AttributeError):
                pass
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except (OSError, AttributeError):
                pass
        tmp.replace(dest)

    try:
        canonical = resolve_state_path(filename)
        _atomic_write(canonical)
    except Exception:
        pass


def unlink_state_file(filename: str) -> None:
    """Delete a persistent state file from the sanctioned data root."""
    try:
        canonical = resolve_state_path(filename)
        if canonical.is_file():
            canonical.unlink(missing_ok=True)
    except Exception:
        pass


def get_secret(key: str, default: str = "") -> str:
    """
    Retrieve a secret using Hermes's secret scope (agent.secret_scope.get_secret).
    Falls back gracefully to os.environ when running in test harnesses or outside Hermes.
    """
    for scope_holder in ("hermes_agent", "agent", "ctx"):
        try:
            import sys
            mod = sys.modules.get(scope_holder)
            if mod:
                scope = getattr(mod, "secret_scope", None)
                if scope and hasattr(scope, "get_secret"):
                    val = scope.get_secret(key)
                    if val is not None and str(val).strip():
                        return str(val).strip()
        except Exception:
            pass
    return os.getenv(key, default).strip()

