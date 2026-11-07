"""
policy_engine.py — Policy Engine for Hermes SafeGuard.

Supports three operational security modes:
  - strict: Aggressive blocking (default). Strict value caps, zero-slippage swap protection,
            unbounded approvals blocked, strict whitelist enforcement.
  - balanced: Higher value limits and standard token approvals, but still blocks obvious
              drains (unbounded approvals, drain selectors, slippage = 0) and requires simulation.
  - degen: Relaxed value and approval limits for NFT minting and heavy contract interactions.
           Allows unlimited approvals and relaxed swap slippage for whitelisted contracts,
           while still strictly enforcing pre-flight simulation, unexpected balance-loss checks,
           and blocking known malicious patterns (smuggled drains, denylisted recipients).

Supports configuration via Python dict and YAML format.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, TextIO

try:
    import yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False


# Default address constants
DEFAULT_ALLOWED_TARGET = "0x000000000000000000000000000000000000BEEF"

# Known function selectors matching SafeGuardPolicy.sol
APPROVE_SELECTOR = "095ea7b3"
TRANSFER_FROM_SELECTOR = "23b872dd"
CHECK_TRANSACTION_SELECTOR = "5ccc6a65"
MULTICALL_SELECTOR = "ac9650d8"
V2_SWAP_SELECTOR = "38ed1739"
V3_SWAP_SELECTOR = "414bf389"
SET_APPROVAL_FOR_ALL_SELECTOR = "a22cb465"
PERMIT2_APPROVE_SELECTOR = "87517c45"
EXPLOIT_DELEGATECALL_SELECTOR = "de1e9a7e"

# Standard uint256 max
UINT256_MAX = (1 << 256) - 1


class PolicyMode(str, Enum):
    """Supported policy operational modes."""
    STRICT = "strict"
    BALANCED = "balanced"
    DEGEN = "degen"


class RiskScore(str, Enum):
    """Transaction risk levels for SafeGuard inspection."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationResult(tuple):
    """
    Result object representing policy or simulation verification.
    Behaves as a 2-tuple (allowed, reason) or 3-tuple (allowed, reason, risk_score)
    when unpacked, and provides attribute access (.allowed, .reason, .risk_score, .warning).
    """
    allowed: bool
    reason: str
    risk_score: str
    warning: str

    def __new__(
        cls,
        allowed: bool,
        reason: str = "",
        risk_score: str | RiskScore = RiskScore.LOW,
        warning: str = "",
    ):
        risk_val = risk_score.value if isinstance(risk_score, RiskScore) else str(risk_score)
        inst = super().__new__(cls, (bool(allowed), str(reason), risk_val))
        inst.allowed = bool(allowed)
        inst.reason = str(reason)
        inst.risk_score = risk_val
        inst.risk = risk_val
        inst.warning = str(warning)
        return inst

    def __iter__(self):
        try:
            import sys, dis
            f = sys._getframe(1)
            for instr in dis.get_instructions(f.f_code):
                if instr.offset == f.f_lasti and instr.opname == "UNPACK_SEQUENCE":
                    if instr.arg == 2:
                        return iter((self.allowed, self.reason))
                    elif instr.arg == 3:
                        return iter((self.allowed, self.reason, self.risk_score))
        except Exception:
            pass
        return super().__iter__()


def normalize_address(address: str) -> str:
    """Normalize hex address string to 40 lowercase hex characters without prefix."""
    addr = str(address).strip()
    if addr.startswith(("0x", "0X")):
        addr = addr[2:]
    if len(addr) > 40:
        addr = addr[-40:]
    return addr.rjust(40, "0").lower()


def _parse_wei_value(val: int | float | str | None, default: int) -> int:
    """
    Parse native asset amount in wei from int, float (interpreted as ETH if float),
    or string with optional 'eth' / 'ether' / '0x' suffix/prefix.
    """
    if val is None:
        return default
    if isinstance(val, float):
        return int(val * 10**18)
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip().lower()
        if s.endswith("ether"):
            num = float(s[:-5].strip())
            return int(num * 10**18)
        if s.endswith("eth"):
            num = float(s[:-3].strip())
            return int(num * 10**18)
        if s.startswith("0x"):
            return int(s, 16)
        if "." in s:
            return int(float(s) * 10**18)
        return int(s)
    return default


def _parse_token_value(val: int | float | str | None, default: int) -> int:
    """Parse token cap value from int, float, or string."""
    if val is None:
        return default
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str):
        s = val.strip().lower()
        if s.startswith("0x"):
            return int(s, 16)
        if "." in s:
            return int(float(s))
        return int(s)
    return default


def decode_bytes_array(data: bytes) -> list[bytes]:
    """Decode ABI-encoded bytes[] dynamic array."""
    if len(data) < 64:
        return []
    offset_arr = int.from_bytes(data[:32], "big")
    if len(data) < offset_arr + 32:
        return []
    count = int.from_bytes(data[offset_arr : offset_arr + 32], "big")
    offsets: list[int] = []
    for i in range(count):
        start = offset_arr + 32 + i * 32
        if len(data) < start + 32:
            return []
        off = int.from_bytes(data[start : start + 32], "big")
        offsets.append(offset_arr + 32 + off)

    res: list[bytes] = []
    for off in offsets:
        if len(data) < off + 32:
            return []
        length = int.from_bytes(data[off : off + 32], "big")
        if len(data) < off + 32 + length:
            return []
        res.append(data[off + 32 : off + 32 + length])
    return res


@dataclass
class PolicyConfig:
    """
    Configuration structure for Hermes SafeGuard policy verification.

    Controls:
      - mode: 'strict', 'balanced', or 'degen'
      - max_eth_per_tx: Maximum native ETH (in wei) allowed per transaction
      - max_token_per_tx: Maximum token amount allowed per approval/tx
      - allow_unlimited_approve: Whether type(uint256).max approvals are allowed (always False in strict/balanced)
      - require_simulation: Whether pre-flight execution simulation is required (always True across all modes)
      - block_zero_slippage: Whether zero-slippage swaps are blocked (always True in strict/balanced)
      - recipient_allowlist: List of allowed recipient addresses
      - recipient_denylist: List of explicitly blocked addresses (blocked in all modes)
      - contract_allowlist: Whitelist of allowed contracts for heavy interactions in degen mode
    """

    mode: str = "strict"
    max_eth_per_tx: int | None = None
    max_token_per_tx: int | None = None
    allow_unlimited_approve: bool | None = None
    require_simulation: bool = True
    block_zero_slippage: bool | None = None
    recipient_allowlist: list[str] | None = None
    recipient_denylist: list[str] = field(default_factory=list)
    contract_allowlist: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Normalize mode string
        self.mode = str(self.mode).lower().strip()
        if self.mode not in ("strict", "balanced", "degen"):
            raise ValueError(
                f"Invalid policy mode: '{self.mode}'. Must be one of: 'strict', 'balanced', 'degen'."
            )

        # Mode-specific defaults
        if self.mode == "strict":
            if self.max_eth_per_tx is None:
                self.max_eth_per_tx = 500_000_000_000_000_000  # 0.5 ETH
            if self.max_token_per_tx is None:
                self.max_token_per_tx = 500_000_000_000_000_000
            if self.allow_unlimited_approve is None:
                self.allow_unlimited_approve = False
            if self.block_zero_slippage is None:
                self.block_zero_slippage = True
            if self.recipient_allowlist is None:
                self.recipient_allowlist = [DEFAULT_ALLOWED_TARGET]
        elif self.mode == "balanced":
            if self.max_eth_per_tx is None:
                self.max_eth_per_tx = 5_000_000_000_000_000_000  # 5.0 ETH
            if self.max_token_per_tx is None:
                self.max_token_per_tx = 50_000_000_000_000_000_000  # 50 tokens
            if self.allow_unlimited_approve is None:
                self.allow_unlimited_approve = False
            if self.block_zero_slippage is None:
                self.block_zero_slippage = True
            if self.recipient_allowlist is None:
                self.recipient_allowlist = [DEFAULT_ALLOWED_TARGET]
        else:  # degen
            if self.max_eth_per_tx is None:
                self.max_eth_per_tx = 100_000_000_000_000_000_000  # 100.0 ETH
            if self.max_token_per_tx is None:
                self.max_token_per_tx = UINT256_MAX
            if self.allow_unlimited_approve is None:
                self.allow_unlimited_approve = True
            if self.block_zero_slippage is None:
                self.block_zero_slippage = False
            if self.recipient_allowlist is None:
                self.recipient_allowlist = []

        # Ensure recipient_allowlist is a list
        if self.recipient_allowlist is None:
            self.recipient_allowlist = []

        # Parse amounts if given as string/float
        self.max_eth_per_tx = _parse_wei_value(self.max_eth_per_tx, 500_000_000_000_000_000)
        self.max_token_per_tx = _parse_token_value(self.max_token_per_tx, 500_000_000_000_000_000)

        # Enforce invariant: require_simulation is ALWAYS True
        self.require_simulation = True

        # Enforce invariant: allow_unlimited_approve is False in strict and balanced
        if self.mode in ("strict", "balanced"):
            self.allow_unlimited_approve = False

        # Enforce invariant: block_zero_slippage is True in strict and balanced
        if self.mode in ("strict", "balanced"):
            self.block_zero_slippage = True

    @classmethod
    def strict(
        cls,
        max_eth_per_tx: int | float | str | None = None,
        max_token_per_tx: int | float | str | None = None,
        recipient_allowlist: list[str] | None = None,
        recipient_denylist: list[str] | None = None,
    ) -> PolicyConfig:
        """Create a strict mode PolicyConfig (aggressive blocking, default for most users)."""
        eth_cap = _parse_wei_value(max_eth_per_tx, 500_000_000_000_000_000)  # 0.5 ETH
        token_cap = _parse_token_value(max_token_per_tx, 500_000_000_000_000_000)
        allowlist = recipient_allowlist if recipient_allowlist is not None else [DEFAULT_ALLOWED_TARGET]
        denylist = recipient_denylist if recipient_denylist is not None else []
        return cls(
            mode="strict",
            max_eth_per_tx=eth_cap,
            max_token_per_tx=token_cap,
            allow_unlimited_approve=False,
            require_simulation=True,
            block_zero_slippage=True,
            recipient_allowlist=allowlist,
            recipient_denylist=denylist,
            contract_allowlist=[],
        )

    @classmethod
    def balanced(
        cls,
        max_eth_per_tx: int | float | str | None = None,
        max_token_per_tx: int | float | str | None = None,
        recipient_allowlist: list[str] | None = None,
        recipient_denylist: list[str] | None = None,
    ) -> PolicyConfig:
        """Create a balanced mode PolicyConfig (higher amounts, capped approvals, blocks drains)."""
        eth_cap = _parse_wei_value(max_eth_per_tx, 5_000_000_000_000_000_000)  # 5.0 ETH
        token_cap = _parse_token_value(max_token_per_tx, 50_000_000_000_000_000_000)  # 50 ETH equiv
        allowlist = recipient_allowlist if recipient_allowlist is not None else []
        denylist = recipient_denylist if recipient_denylist is not None else []
        return cls(
            mode="balanced",
            max_eth_per_tx=eth_cap,
            max_token_per_tx=token_cap,
            allow_unlimited_approve=False,
            require_simulation=True,
            block_zero_slippage=True,
            recipient_allowlist=allowlist,
            recipient_denylist=denylist,
            contract_allowlist=[],
        )

    @classmethod
    def degen(
        cls,
        max_eth_per_tx: int | float | str | None = None,
        max_token_per_tx: int | float | str | None = None,
        allow_unlimited_approve: bool = True,
        block_zero_slippage: bool = False,
        contract_allowlist: list[str] | None = None,
        recipient_allowlist: list[str] | None = None,
        recipient_denylist: list[str] | None = None,
    ) -> PolicyConfig:
        """Create a degen mode PolicyConfig (relaxed amount & approvals for NFT/heavy interaction)."""
        eth_cap = _parse_wei_value(max_eth_per_tx, 100_000_000_000_000_000_000)  # 100.0 ETH
        token_cap = _parse_token_value(max_token_per_tx, UINT256_MAX)
        contracts = contract_allowlist if contract_allowlist is not None else []
        allowlist = recipient_allowlist if recipient_allowlist is not None else []
        denylist = recipient_denylist if recipient_denylist is not None else []
        return cls(
            mode="degen",
            max_eth_per_tx=eth_cap,
            max_token_per_tx=token_cap,
            allow_unlimited_approve=allow_unlimited_approve,
            require_simulation=True,
            block_zero_slippage=block_zero_slippage,
            recipient_allowlist=allowlist,
            recipient_denylist=denylist,
            contract_allowlist=contracts,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyConfig:
        """Instantiate PolicyConfig from a Python dictionary."""
        mode = str(data.get("mode", "strict")).lower().strip()

        # Handle alias keys
        rec_allowlist = data.get("recipient_allowlist", data.get("allowlist", data.get("whitelist")))
        rec_denylist = data.get("recipient_denylist", data.get("denylist", []))
        contracts = data.get("contract_allowlist", data.get("contracts", []))

        if mode == "strict":
            default_eth = 500_000_000_000_000_000
            default_tok = 500_000_000_000_000_000
            default_allow = [DEFAULT_ALLOWED_TARGET] if rec_allowlist is None else rec_allowlist
            default_unlim = False
            default_slip = True
        elif mode == "balanced":
            default_eth = 5_000_000_000_000_000_000
            default_tok = 50_000_000_000_000_000_000
            default_allow = [] if rec_allowlist is None else rec_allowlist
            default_unlim = False
            default_slip = True
        else:  # degen
            default_eth = 100_000_000_000_000_000_000
            default_tok = UINT256_MAX
            default_allow = [] if rec_allowlist is None else rec_allowlist
            default_unlim = True
            default_slip = False

        max_eth = _parse_wei_value(data.get("max_eth_per_tx"), default_eth)
        max_tok = _parse_token_value(data.get("max_token_per_tx"), default_tok)
        unlim_approve = bool(data.get("allow_unlimited_approve", default_unlim))
        zero_slip = bool(data.get("block_zero_slippage", default_slip))

        return cls(
            mode=mode,
            max_eth_per_tx=max_eth,
            max_token_per_tx=max_tok,
            allow_unlimited_approve=unlim_approve,
            require_simulation=True,  # always True
            block_zero_slippage=zero_slip,
            recipient_allowlist=list(default_allow),
            recipient_denylist=list(rec_denylist),
            contract_allowlist=list(contracts),
        )

    @classmethod
    def from_yaml(cls, content: str | Path | TextIO) -> PolicyConfig:
        """Load PolicyConfig from YAML string, file path, or file-like object."""
        raw_text = ""
        if isinstance(content, Path) or (isinstance(content, str) and os.path.isfile(content)):
            with open(content, "r", encoding="utf-8") as f:
                raw_text = f.read()
        elif hasattr(content, "read"):
            raw_text = content.read()
        elif isinstance(content, str):
            raw_text = content
        else:
            raise TypeError(f"Unsupported content type for YAML loading: {type(content)}")

        if _HAVE_YAML:
            loaded = yaml.safe_load(raw_text) or {}
            if not isinstance(loaded, dict):
                raise ValueError("YAML content must deserialize to a dictionary mapping.")
            return cls.from_dict(loaded)
        else:
            # Fallback basic YAML parser for standard key-value structures
            import json
            try:
                loaded = json.loads(raw_text)
                return cls.from_dict(loaded)
            except Exception as e:
                raise RuntimeError("PyYAML not available to parse YAML configuration") from e

    def to_dict(self) -> dict[str, Any]:
        """Convert PolicyConfig to a Python dictionary."""
        return asdict(self)

    def to_yaml(self) -> str:
        """Serialize PolicyConfig to a YAML string."""
        d = self.to_dict()
        if _HAVE_YAML:
            return yaml.safe_dump(d, sort_keys=False)
        else:
            import json
            return json.dumps(d, indent=2)


class PolicyEngine:
    """
    Stateless transaction policy verification engine.

    Evaluates transactions against strict, balanced, or degen policy rules:
      1. Recipient denylist verification (blocks known malicious contracts).
      2. Allowlist checks (strict whitelist, degen contract allowlist).
      3. Value cap checks (native ETH per tx).
      4. Calldata inspection (unbounded approvals, smuggled multicall drainers, slippage protection).
    """

    def __init__(self, config: PolicyConfig | dict[str, Any] | None = None) -> None:
        if config is None:
            self.config = PolicyConfig.strict()
        elif isinstance(config, dict):
            self.config = PolicyConfig.from_dict(config)
        elif isinstance(config, PolicyConfig):
            self.config = config
        else:
            raise TypeError(f"Invalid config type: {type(config)}. Expected PolicyConfig or dict.")

        # Pre-normalize addresses for O(1) set membership lookup
        self.denylist: set[str] = {normalize_address(a) for a in self.config.recipient_denylist}
        self.recipient_allowlist: set[str] = {normalize_address(a) for a in self.config.recipient_allowlist}
        self.contract_allowlist: set[str] = {normalize_address(a) for a in self.config.contract_allowlist}

    def evaluate_calldata_security(self, inner_data_hex: str) -> str | None:
        """
        Recursively evaluate calldata against policy security rules.
        Returns None if calldata is allowed, or an error string (e.g. 'SG: selector blocked').
        """
        raw = inner_data_hex.strip()
        if raw.startswith(("0x", "0X")):
            raw = raw[2:]
        if len(raw) < 8:
            return None

        sel = raw[:8].lower()

        # 1. Blocked drain selectors: transferFrom is blocked across all modes (strict, balanced, degen)
        if sel == TRANSFER_FROM_SELECTOR:
            return "SG: selector blocked"

        # 2. ERC-20 approve(address,uint256)
        if sel == APPROVE_SELECTOR:
            if len(raw) < 136:
                return "SG: malformed approve calldata"
            amount = int(raw[72:136], 16)
            if amount == UINT256_MAX:
                if not self.config.allow_unlimited_approve:
                    return "SG: unbounded approve blocked"
            elif amount > self.config.max_token_per_tx:
                return "SG: approve amount exceeds token cap"

        # 3. Recursive Multicall Unpacking: multicall(bytes[])
        if sel == MULTICALL_SELECTOR:
            if len(raw) < 72:
                return "SG: malformed multicall calldata"
            try:
                raw_bytes = bytes.fromhex(raw[8:])
                sub_calls = decode_bytes_array(raw_bytes)
            except Exception:
                return "SG: malformed multicall calldata"
            for call_b in sub_calls:
                err = self.evaluate_calldata_security(call_b.hex())
                if err:
                    return err

        # 4. Zero-Slippage Swap Protection: Uniswap V2
        if sel == V2_SWAP_SELECTOR:
            if len(raw) < 136:
                return "SG: malformed swap calldata"
            amount_out_min = int(raw[72:136], 16)
            if amount_out_min == 0 and self.config.block_zero_slippage:
                return "SG: zero slippage swap blocked"

        # 5. Zero-Slippage Swap Protection: Uniswap V3
        if sel == V3_SWAP_SELECTOR:
            if len(raw) < 456:
                return "SG: malformed swap calldata"
            amount_out_min = int(raw[392:456], 16)
            if amount_out_min == 0 and self.config.block_zero_slippage:
                return "SG: zero slippage swap blocked"

        # 6. Modern Drainer Selectors: setApprovalForAll(address,bool)
        if sel == SET_APPROVAL_FOR_ALL_SELECTOR:
            if len(raw) < 136:
                return "SG: malformed approval calldata"
            approved = int(raw[72:136], 16) != 0
            if approved and not self.config.allow_unlimited_approve:
                return "SG: setApprovalForAll blocked"

        # 7. Modern Drainer Selectors: Permit2 approve(address,address,uint160,uint48)
        if sel == PERMIT2_APPROVE_SELECTOR:
            if len(raw) < 200:
                return "SG: malformed permit2 calldata"
            amount = int(raw[136:200], 16)
            if amount > self.config.max_token_per_tx:
                return "SG: permit2 amount exceeds cap"

        return None

    def evaluate_transaction_policy(
        self, to_address: str, value_wei: int, data_hex: str = ""
    ) -> VerificationResult:
        """
        Verify transaction parameters against all policy rules for the configured mode.

        Returns:
            VerificationResult(allowed: bool, reason: str, risk_score: str)
        """
        target_norm = normalize_address(to_address)

        # 1. Recipient Denylist (enforced in all modes: strict, balanced, degen)
        if target_norm in self.denylist:
            return VerificationResult(False, "SG: recipient is denylisted", RiskScore.CRITICAL)

        # 2. Allowlist checks
        if self.config.mode == "strict":
            if self.recipient_allowlist and target_norm not in self.recipient_allowlist:
                return VerificationResult(False, "SG: target not whitelisted", RiskScore.MEDIUM)
        elif self.config.mode == "balanced":
            if self.recipient_allowlist and target_norm not in self.recipient_allowlist:
                return VerificationResult(False, "SG: target not whitelisted", RiskScore.MEDIUM)
        elif self.config.mode == "degen":
            # In degen mode, if a contract_allowlist is configured, verify contract interactions
            if self.contract_allowlist:
                if (target_norm not in self.contract_allowlist) and (target_norm not in self.recipient_allowlist):
                    return VerificationResult(False, "SG: target not in degen contract allowlist", RiskScore.MEDIUM)
            elif self.recipient_allowlist:
                if target_norm not in self.recipient_allowlist:
                    return VerificationResult(False, "SG: target not whitelisted", RiskScore.MEDIUM)

        # 3. Value Cap check
        if value_wei > self.config.max_eth_per_tx:
            return VerificationResult(False, "SG: value exceeds max per tx", RiskScore.HIGH)

        # 4. Calldata security evaluation
        raw_data = data_hex.strip() if data_hex else ""
        if raw_data.startswith(("0x", "0X")):
            raw_data = raw_data[2:]

        if len(raw_data) >= 8:
            calldata_err = self.evaluate_calldata_security(raw_data)
            if calldata_err:
                risk = RiskScore.HIGH
                if "selector blocked" in calldata_err:
                    risk = RiskScore.CRITICAL
                elif "exceeds" in calldata_err:
                    risk = RiskScore.MEDIUM
                return VerificationResult(False, calldata_err, risk)

        return VerificationResult(True, "", RiskScore.LOW)
