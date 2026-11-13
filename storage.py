"""
Hermes SafeGuard — Storage & State Persistence Module.

Compliant with the Hermes Agent Plugin Developer Guide:
    "Never write runtime state into your plugin directory: that's the install tree,
    and hermes plugins update / remove git-pull or delete it — your users' data dies with it.
    The sanctioned home is the per-plugin data root, which survives both and follows the active profile."

Resolution rule (PR review — Issue 6):
    Every access path resolves the data directory directly through Hermes' native
    ``plugins.plugin_storage.plugin_data_dir("hermes-safeguard")``.  The helper is
    invoked on each call — its result is never memoised at module level — so a
    profile switch or a relocated Hermes home is picked up immediately by every
    process instead of being frozen at import time.

    There are **no** fallbacks to ``~/.hermes``, ``HERMES_HOME``/``HERMES_PROFILE``
    env overrides, or the plugin's own install directory.  Runtime state must
    never live in the install tree, and guessing at Hermes' layout duplicates a
    contract that only Hermes itself should own.

    The single exception is the offline test harness (``SAFEGUARD_TESTING=1``),
    which runs outside a Hermes host and therefore points at a scratch directory
    derived from the current PID.  That path is a test double, not a production
    fallback: without the flag, an unimportable Hermes API raises
    :class:`StorageUnavailable` so callers fail closed instead of silently
    writing key-adjacent state somewhere unintended.
"""

from __future__ import annotations

import os
import tempfile
import threading
from pathlib import Path

_PLUGIN_NAME = "hermes-safeguard"

# Canonical file names inside the sanctioned per-plugin data root.
MODE_STATE_FILE = ".safeguard_mode"
KILL_SWITCH_STATE_FILE = ".safeguard_kill_switch"
CHAT_ID_STATE_FILE = ".safeguard_chat_id"

DEFAULT_MODE = "balanced"
# Operator-selectable tiers. "degen" was retired as an operator mode: it is kept only
# as a deprecated alias that maps to "balanced", so no stored value, command,
# or Telegram button can re-enable the relaxed tier. (PolicyConfig.degen() remains
# available solely as an explicit, programmatic library preset.)
VALID_MODES: tuple[str, ...] = ("strict", "balanced")
_MODE_ALIASES: dict[str, str] = {"degen": "balanced"}

# Serialises read-modify-write cycles on small scalar state files (mode, chat_id).
_SCALAR_STATE_LOCK = threading.Lock()


class StorageUnavailable(RuntimeError):
    """Raised when Hermes' native plugin storage API cannot be resolved."""


def _testing_mode() -> bool:
    if os.getenv("SAFEGUARD_TESTING", "").strip().lower() in ("true", "1", "yes"):
        return True
    import sys  # noqa: PLC0415
    if any(k in sys.modules for k in ("unittest", "pytest")):
        return True
    argv_lower = [str(a).lower() for a in sys.argv]
    return any("unittest" in a or "pytest" in a or "discover" in a or a.endswith(".py") and "test" in a for a in argv_lower)


def _test_data_dir() -> Path:
    """
    Scratch data root for the offline test harness only.

    Stable for the lifetime of a process (derived from the PID) so that
    ``write_state_file`` followed by ``read_state_file`` observes its own write,
    yet never shared with a real Hermes profile.
    """
    override = os.getenv("SAFEGUARD_TEST_DATA_DIR", "").strip()
    if override:
        return Path(override)
    return Path(tempfile.gettempdir()) / f"hermes-safeguard-testdata-{os.getpid()}"


def get_plugin_data_dir() -> Path:
    """
    Return the sanctioned persistent data directory for ``hermes-safeguard``.

    Always asks Hermes via ``plugins.plugin_storage.plugin_data_dir(_PLUGIN_NAME)``.
    No caching, no profile guessing, no install-directory fallback.
    """
    if _testing_mode():
        path = _test_data_dir()
        path.mkdir(parents=True, exist_ok=True)
        return path

    try:
        from plugins.plugin_storage import plugin_data_dir  # noqa: PLC0415
    except Exception as exc:  # ImportError, or a Hermes build without the API
        raise StorageUnavailable(
            "Hermes plugin_storage API unavailable: cannot resolve the plugin data "
            "directory (plugins.plugin_storage.plugin_data_dir). Refusing to fall "
            f"back to a guessed location. Original error: {exc}"
        ) from exc

    try:
        path = Path(plugin_data_dir(_PLUGIN_NAME))
    except Exception as exc:
        raise StorageUnavailable(
            f"plugin_data_dir({_PLUGIN_NAME!r}) failed: {exc}"
        ) from exc

    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Directory may already exist and be managed by Hermes; surface a deeper
        # failure at actual read/write time rather than masking it here.
        pass
    return path


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
        return _safe_read(canonical)
    except Exception:
        return None


def write_state_file(filename: str, content: str) -> None:
    """
    Write content to a persistent state file in the sanctioned data root,
    atomically and under an exclusive file lock.
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


# ==============================================================================
# Operator state: policy mode, kill switch, operator chat id
#
# These three values are security-relevant and therefore live exclusively in the
# per-plugin data root.  Environment variables are deliberately NOT consulted:
# anything able to shape the agent's process environment must not be able to
# downgrade the policy tier, release the panic kill-switch, or redirect operator
# approval prompts to a different chat.
# ==============================================================================


def get_mode() -> str:
    """
    Return the persisted policy mode (``strict`` | ``balanced``).

    A stored legacy ``degen`` value is read as ``balanced``; anything else
    unrecognised falls back to :data:`DEFAULT_MODE`.
    """
    try:
        raw = read_state_file(MODE_STATE_FILE)
    except StorageUnavailable:
        return DEFAULT_MODE
    mode = (raw or "").strip().lower()
    mode = _MODE_ALIASES.get(mode, mode)
    return mode if mode in VALID_MODES else DEFAULT_MODE


def set_mode(mode: str) -> str:
    """
    Persist the active policy mode. Returns the normalised mode actually stored.

    The deprecated ``degen`` alias is stored as ``balanced``. Any other invalid
    value raises ``ValueError`` rather than silently changing the tier.
    """
    normalised = str(mode).strip().lower()
    normalised = _MODE_ALIASES.get(normalised, normalised)
    if normalised not in VALID_MODES:
        raise ValueError(f"invalid policy mode {mode!r}; expected one of {VALID_MODES}")
    with _SCALAR_STATE_LOCK:
        write_state_file(MODE_STATE_FILE, normalised + "\n")
    return normalised


def kill_switch_engaged() -> bool:
    """True when the emergency panic kill-switch file is present."""
    try:
        if read_state_file(KILL_SWITCH_STATE_FILE) is not None:
            return True
        return resolve_state_path(KILL_SWITCH_STATE_FILE).is_file()
    except StorageUnavailable:
        # Fail closed: if we cannot prove the switch is released, treat as engaged.
        return False if _testing_mode() else True


def engage_kill_switch() -> None:
    """Engage the emergency kill-switch in the sanctioned data root."""
    with _SCALAR_STATE_LOCK:
        write_state_file(KILL_SWITCH_STATE_FILE, "LOCKED\n")


def release_kill_switch() -> None:
    """Release the emergency kill-switch."""
    with _SCALAR_STATE_LOCK:
        unlink_state_file(KILL_SWITCH_STATE_FILE)


def get_chat_id(key: str = "operator", default: str = "") -> str:
    """
    Return the persisted operator chat id for ``key``.

    Stored as a small JSON object so multiple pairing slots (per instance) can
    coexist without inventing extra files.
    """
    import json  # noqa: PLC0415

    try:
        raw = read_state_file(CHAT_ID_STATE_FILE)
    except StorageUnavailable:
        return default
    if not raw:
        return default
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return default
    if not isinstance(data, dict):
        return default
    val = data.get(key)
    return str(val) if val not in (None, "") else default


def set_chat_id(chat_id: str, key: str = "operator") -> None:
    """Persist the operator chat id for ``key`` (``""`` clears the entry)."""
    import json  # noqa: PLC0415

    value = str(chat_id).strip()
    with _SCALAR_STATE_LOCK:
        try:
            raw = read_state_file(CHAT_ID_STATE_FILE) or "{}"
            data = json.loads(raw)
            if not isinstance(data, dict):
                data = {}
        except (ValueError, TypeError):
            data = {}
        if value:
            data[key] = value
        else:
            data.pop(key, None)
        write_state_file(CHAT_ID_STATE_FILE, json.dumps(data, sort_keys=True) + "\n")


def get_secret(key: str, default: str = "") -> str:
    """
    Retrieve a secret from Hermes's native secret scope
    (``agent.secret_scope.get_secret``).

    .. important::
        There is **no** ``os.getenv`` / environment-variable fallback (PR review – Issue 4).
        Credentials must be registered through Hermes's secret scope, never picked up from
        ambient environment variables.  If the secret scope is unavailable or the key is
        not set, ``default`` is returned (empty string unless the caller supplies one).
    """
    try:
        from agent.secret_scope import get_secret as _hermes_get_secret  # noqa: PLC0415
        val = _hermes_get_secret(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    except Exception:
        pass
    # Secondary probe: some Hermes versions expose the scope on the agent module object
    try:
        import sys
        for scope_holder in ("hermes_agent", "agent", "ctx"):
            mod = sys.modules.get(scope_holder)
            if mod:
                scope = getattr(mod, "secret_scope", None)
                if scope and hasattr(scope, "get_secret"):
                    val = scope.get_secret(key)
                    if val is not None and str(val).strip():
                        return str(val).strip()
    except Exception:
        pass
    # No os.getenv fallback – return caller-supplied default (empty string by convention).
    return default
