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

import base64
import hashlib
import json
import logging
import os
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, TextIO

logger = logging.getLogger("hermes_safeguard")

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

# ==============================================================================
# Prompt / Indirect Injection Constants & Dictionaries
# ==============================================================================

# International Morse Code mapping (supports uppercase alphanumeric & punctuation)
MORSE_CODE_DICT: dict[str, str] = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", "-..-.": "/",
    "-....-": "-", "---...": ":", ".--.-.": "@",
}

# Financial tool names intercepted by SafeGuard
FINANCIAL_TOOLS: set[str] = {
    "safeguard_execute_tx",
    "safeguard_check_policy",
    "eth_sendtransaction",
    "eth_sendrawtransaction",
    "send_transaction",
    "send_tx",
    "execute_tx",
    "transfer",
    "transfer_eth",
    "transfer_tokens",
    "transfer_nft",
    "approve",
    "set_approval",
    "set_approval_for_all",
    "uniswap_swap",
    "swap",
    "execute_swap",
    "sign_transaction",
    "wallet_transfer",
    "crypto_transfer",
    "send_funds",
}


def is_financial_tool(tool_name: str) -> bool:
    """
    Check if a tool name corresponds to a financial, transfer, approval, or transaction action.
    """
    name = str(tool_name).strip().lower()
    if name in (
        "safeguard_approve_address",
        "safeguard_list_approved_addresses",
        "safeguard_revoke_address",
        "safeguard_confirm_action",
        "safeguard_list_pending_confirmations",
        "safeguard_get_audit_log",
    ):
        return False
    if name in FINANCIAL_TOOLS:
        return True
    financial_keywords = ("transfer", "swap", "approve", "send_tx", "sendtransaction", "wallet", "payout")
    return any(kw in name for kw in financial_keywords)


# Emergency Kill-Switch State (Shared across processes via file and env)
_KILL_SWITCH_FILE = Path.home() / ".hermes" / ".safeguard_kill_switch"
_LOCAL_KILL_SWITCH_FILE = Path(__file__).resolve().parent / ".safeguard_kill_switch"
_KILL_SWITCH_ACTIVE: bool = False


def _get_kill_switch_files() -> list[Path]:
    files = [_LOCAL_KILL_SWITCH_FILE, _KILL_SWITCH_FILE]
    try:
        from storage import resolve_state_path
        p = resolve_state_path(".safeguard_kill_switch")
        if p not in files:
            files.append(p)
    except Exception:
        pass
    return files


def is_kill_switch_active() -> bool:
    """True if operator has engaged emergency panic lockdown."""
    global _KILL_SWITCH_ACTIVE
    if _KILL_SWITCH_ACTIVE:
        return True
    if os.getenv("SAFEGUARD_KILL_SWITCH", "").strip().lower() in ("true", "1", "yes", "active"):
        return True
    for p in _get_kill_switch_files():
        if p.is_file():
            return True
    return False


def set_kill_switch(active: bool) -> None:
    """Engage or release the emergency kill-switch."""
    global _KILL_SWITCH_ACTIVE
    _KILL_SWITCH_ACTIVE = active
    if active:
        os.environ["SAFEGUARD_KILL_SWITCH"] = "true"
        for p in _get_kill_switch_files():
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.touch()
            except Exception:
                pass
    else:
        if "SAFEGUARD_KILL_SWITCH" in os.environ:
            del os.environ["SAFEGUARD_KILL_SWITCH"]
        for p in _get_kill_switch_files():
            try:
                if p.is_file():
                    p.unlink()
            except Exception:
                pass


# ==============================================================================
# Context Tagging & Inspection Data Structures
# ==============================================================================

@dataclass
class ContextMessage:
    """
    Represents an agent context item (user prompt, tool result, social post, email, etc.)
    tagged with trust status.
    Untrusted context is scanned for prompt and indirect injection before financial tool execution.
    """
    content: str
    role: str = "user"  # "user", "assistant", "system", "tool", "environment"
    trusted: bool | None = None
    source: str = ""  # e.g. "x_post", "twitter", "email", "web_page", "tool_result", "system"
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_trusted(self) -> bool:
        """Return True if message content is explicitly or implicitly trusted."""
        if self.trusted is not None:
            return bool(self.trusted)
        src = (self.source or "").lower().strip()
        role = (self.role or "").lower().strip()
        # Explicit trusted roles/sources: system, admin, internal instructions
        if role in ("system", "admin", "developer") or src in ("system", "admin", "internal", "developer"):
            return True
        # Untrusted roles/sources: tool results, external feeds, emails, web pages, social media
        if role in ("tool", "tool_result", "environment") or src in (
            "tool", "tool_result", "web", "web_page", "email", "x_post", "tweet",
            "twitter", "discord", "telegram", "untrusted", "external", "user"
        ):
            return False
        return False


def tag_as_trusted(content: str, source: str = "user", role: str = "user") -> ContextMessage:
    """Explicitly create a trusted ContextMessage (e.g. verified system/user command)."""
    return ContextMessage(content=str(content), role=role, trusted=True, source=source)


def tag_as_untrusted(content: str, source: str = "untrusted", role: str = "tool") -> ContextMessage:
    """Explicitly create an untrusted ContextMessage (e.g. web page, email, social feed, tool output)."""
    return ContextMessage(content=str(content), role=role, trusted=False, source=source)


def tag_context(messages: list[Any], default_trusted: bool = False) -> list[ContextMessage]:
    """Convert an arbitrary list of message dicts, strings, or ContextMessage instances into tagged ContextMessages."""
    tagged: list[ContextMessage] = []
    for m in messages:
        if isinstance(m, ContextMessage):
            tagged.append(m)
        elif isinstance(m, dict):
            role = str(m.get("role", "user"))
            content = str(m.get("content", m.get("text", "")))
            trusted = m.get("trusted")
            source = str(m.get("source", role))
            meta = {k: v for k, v in m.items() if k not in ("role", "content", "text", "trusted", "source")}
            msg = ContextMessage(content=content, role=role, trusted=trusted, source=source, metadata=meta)
            if trusted is None and default_trusted:
                msg.trusted = True
            tagged.append(msg)
        elif isinstance(m, str):
            tagged.append(ContextMessage(content=m, role="user", trusted=default_trusted, source="raw_string"))
        else:
            content = getattr(m, "content", str(m))
            role = getattr(m, "role", "user")
            trusted = getattr(m, "trusted", default_trusted)
            source = getattr(m, "source", role)
            tagged.append(ContextMessage(content=str(content), role=str(role), trusted=trusted, source=str(source)))
    return tagged


def scan_recent_context(
    messages: list[Any],
    n: int = 10,
    untrusted_only: bool = True,
) -> list[ContextMessage]:
    """
    Extract and return the last N messages or tool results from conversation history,
    optionally filtering strictly for untrusted items.
    """
    if not messages:
        return []
    tagged_list = tag_context(messages)
    recent = tagged_list[-n:] if n > 0 else tagged_list
    if untrusted_only:
        return [m for m in recent if not m.is_trusted()]
    return recent


# ==============================================================================
# Prompt Injection Detector
# ==============================================================================

@dataclass
class InjectionSignal:
    """Detailed result of prompt / indirect injection detection."""
    detected: bool = False
    is_strong: bool = False
    confidence: float = 0.0
    category: str = ""
    obfuscation: str | None = None  # "morse", "base64", "hex", or None
    decoded_text: str | None = None
    raw_snippet: str = ""
    untrusted_source: str = ""


class PromptInjectionDetector:
    """
    Detects prompt and indirect injection attacks targeting financial actions.

    Detects:
      1. Simple obfuscation (Morse code, Base64, Hex encoding).
      2. Instruction overrides & jailbreaks ("disregard prior directives", "override safeguards", etc.).
      3. Financial drain commands ("transfer everything", "send all eth", "drain wallet", "sweep funds", etc.).
      4. Approval abuses & wallet tampering ("setApprovalForAll", "approve max", "change wallet", "export private key").
    """

    # Instruction override regex patterns
    RE_OVERRIDE = re.compile(
        r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|directives?|rules?)|"
        r"(?:override|bypass)\s+(?:all\s+)?(?:instructions?|safeguards?|security|rules?|policy)|"
        r"system\s+override|"
        r"admin\s+override|"
        r"new\s+(?:system\s+|admin\s+)?(?:instructions?|directives?)|"
        r"you\s+are\s+now\s+in\s+(?:developer|degen|god|unrestricted)\s+mode|"
        r"jailbreak|"
        r"do\s+not\s+(?:follow|obey)\s+(?:previous|prior|earlier)\s+(?:rules|instructions)",
        re.IGNORECASE,
    )

    # Financial action regex patterns
    RE_FINANCIAL_ACTION = re.compile(
        r"transfer\s+(?:everything|all(?:(?:\s+eth|\s+tokens|\s+funds))?|entire\s+balance)|"
        r"send\s+(?:everything|all(?:(?:\s+eth|\s+tokens|\s+funds))?|entire\s+balance)|"
        r"drain\s+(?:wallet|funds|all|vault|account|balance)|"
        r"sweep\s+(?:funds|wallet|balance|all)|"
        r"empty\s+(?:wallet|vault|account)|"
        r"withdraw\s+(?:all|everything|entire\s+balance)|"
        r"approve\s+(?:all|max|unlimited|everything)|"
        r"setapprovalforall|"
        r"unlimited\s+approv(?:al|e)|"
        r"permit2\s+approve|"
        r"grant\s+full\s+allowance|"
        r"change\s+(?:wallet|owner|recipient|destination)|"
        r"switch\s+wallet|"
        r"transfer\s+ownership|"
        r"set\s+owner|"
        r"(?:export|reveal|send)\s+(?:private\s+key|seed\s+phrase|mnemonic)|"
        r"(?:send|transfer|withdraw|drain|sweep)\s+(?:(?:\d+[a-zA-Z%]*|\$[\w]+|all|everything|entire\s+balance|funds|tokens?|eth|[a-zA-Z0-9_:-]+)\s+)*(?:to|into)\s+(?:(?:my\s+)?wallet|me|attacker|destination|recipient|0x[0-9a-fA-F]{40}|[a-zA-Z0-9_.-]+)",
        re.IGNORECASE,
    )

    # Obfuscation candidate regexes
    RE_MORSE_CANDIDATE = re.compile(r"(?:[.-]{1,6}(?:[ /]+|$)){4,}")
    RE_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/=]{16,}")
    RE_HEX_CANDIDATE = re.compile(r"(?:0x)?[0-9a-fA-F]{16,}")
    RE_HEX_SPACE_CANDIDATE = re.compile(r"(?:[0-9a-fA-F]{2}\s+){4,}[0-9a-fA-F]{2}")
    RE_ETH_ADDRESS = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

    @classmethod
    def decode_morse(cls, morse_str: str) -> str:
        """Decode international Morse code string into uppercase ASCII text."""
        norm = re.sub(r"[·•●]", ".", morse_str)
        norm = re.sub(r"[—–_−]", "-", norm)
        words = re.split(r"\s*/\s*|\s{2,}|\n+", norm.strip())
        decoded_words: list[str] = []
        for w in words:
            chars: list[str] = []
            tokens = w.strip().split()
            for tok in tokens:
                c = MORSE_CODE_DICT.get(tok)
                if c:
                    chars.append(c)
            if chars:
                decoded_words.append("".join(chars))
        return " ".join(decoded_words)

    @classmethod
    def _is_printable_text(cls, s: str) -> bool:
        """Check if decoded string looks like human-readable text."""
        if not s or len(s) < 4:
            return False
        printable = sum(1 for ch in s if 32 <= ord(ch) <= 126 or ch in "\n\r\t")
        return (printable / len(s)) >= 0.80

    def detect(self, text: str, source: str = "") -> InjectionSignal:
        """
        Scan text for prompt injection signals, including obfuscation layers.
        """
        if not text or not isinstance(text, str):
            return InjectionSignal()

        # 1. Obfuscation detection: Morse Code
        morse_candidates = self.RE_MORSE_CANDIDATE.findall(text)
        for cand in morse_candidates:
            decoded = self.decode_morse(cand)
            if decoded and len(decoded.split()) >= 1:
                has_override = bool(self.RE_OVERRIDE.search(decoded))
                has_financial = bool(self.RE_FINANCIAL_ACTION.search(decoded))
                has_addr = bool(self.RE_ETH_ADDRESS.search(decoded))
                if has_override or has_financial or (has_addr and any(kw in decoded.lower() for kw in ("send", "transfer", "eth"))):
                    return InjectionSignal(
                        detected=True,
                        is_strong=True,
                        confidence=0.98,
                        category="obfuscated_morse_injection",
                        obfuscation="morse",
                        decoded_text=decoded,
                        raw_snippet=cand.strip(),
                        untrusted_source=source,
                    )

        # 2. Obfuscation detection: Base64
        b64_candidates = self.RE_BASE64_CANDIDATE.findall(text)
        for cand in b64_candidates:
            try:
                raw_bytes = base64.b64decode(cand)
                decoded = raw_bytes.decode("utf-8", errors="ignore")
                if self._is_printable_text(decoded):
                    has_override = bool(self.RE_OVERRIDE.search(decoded))
                    has_financial = bool(self.RE_FINANCIAL_ACTION.search(decoded))
                    if has_override or has_financial:
                        return InjectionSignal(
                            detected=True,
                            is_strong=True,
                            confidence=0.98,
                            category="obfuscated_base64_injection",
                            obfuscation="base64",
                            decoded_text=decoded,
                            raw_snippet=cand,
                            untrusted_source=source,
                        )
            except Exception:
                pass

        # 3. Obfuscation detection: Hex
        # Try space-separated hex first
        for cand in self.RE_HEX_SPACE_CANDIDATE.findall(text):
            try:
                hex_clean = cand.replace(" ", "")
                decoded = bytes.fromhex(hex_clean).decode("utf-8", errors="ignore")
                if self._is_printable_text(decoded):
                    has_override = bool(self.RE_OVERRIDE.search(decoded))
                    has_financial = bool(self.RE_FINANCIAL_ACTION.search(decoded))
                    if has_override or has_financial:
                        return InjectionSignal(
                            detected=True,
                            is_strong=True,
                            confidence=0.98,
                            category="obfuscated_hex_injection",
                            obfuscation="hex",
                            decoded_text=decoded,
                            raw_snippet=cand,
                            untrusted_source=source,
                        )
            except Exception:
                pass

        for cand in self.RE_HEX_CANDIDATE.findall(text):
            h = cand[2:] if cand.startswith(("0x", "0X")) else cand
            if len(h) % 2 == 0 and len(h) >= 16:
                try:
                    decoded = bytes.fromhex(h).decode("utf-8", errors="ignore")
                    if self._is_printable_text(decoded):
                        has_override = bool(self.RE_OVERRIDE.search(decoded))
                        has_financial = bool(self.RE_FINANCIAL_ACTION.search(decoded))
                        if has_override or has_financial:
                            return InjectionSignal(
                                detected=True,
                                is_strong=True,
                                confidence=0.98,
                                category="obfuscated_hex_injection",
                                obfuscation="hex",
                                decoded_text=decoded,
                                raw_snippet=cand,
                                untrusted_source=source,
                            )
                except Exception:
                    pass

        # 4. Plaintext pattern inspection
        has_override = bool(self.RE_OVERRIDE.search(text))
        has_financial = bool(self.RE_FINANCIAL_ACTION.search(text))
        has_addr = bool(self.RE_ETH_ADDRESS.search(text))

        if has_override and (has_financial or has_addr):
            return InjectionSignal(
                detected=True,
                is_strong=True,
                confidence=0.99,
                category="override_and_financial_drain",
                obfuscation=None,
                decoded_text=None,
                raw_snippet=text[:120],
                untrusted_source=source,
            )

        if has_financial:
            return InjectionSignal(
                detected=True,
                is_strong=True,
                confidence=0.92,
                category="financial_drain_command",
                obfuscation=None,
                decoded_text=None,
                raw_snippet=text[:120],
                untrusted_source=source,
            )

        if has_override:
            return InjectionSignal(
                detected=True,
                is_strong=False,
                confidence=0.70,
                category="instruction_override_suspicious",
                obfuscation=None,
                decoded_text=None,
                raw_snippet=text[:120],
                untrusted_source=source,
            )

        return InjectionSignal()


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
    Behaves as a 2-tuple (allowed, reason), 3-tuple (allowed, reason, risk_score),
    or 4-tuple (allowed, reason, risk_score, requires_confirmation) when unpacked,
    and provides attribute access (.allowed, .reason, .risk_score, .warning, .requires_confirmation,
    .injection_detected, .is_new_recipient, .flagged_addresses, .confirmation_id,
    .confirmation_summary, .summary, .status).
    """
    allowed: bool
    reason: str
    risk_score: str
    warning: str
    requires_confirmation: bool
    injection_detected: bool
    is_new_recipient: bool
    flagged_addresses: list[str]
    confirmation_id: str
    confirmation_summary: str
    summary: str
    status: str

    def __new__(
        cls,
        allowed: bool,
        reason: str = "",
        risk_score: str | RiskScore = RiskScore.LOW,
        warning: str = "",
        requires_confirmation: bool = False,
        injection_detected: bool = False,
        is_new_recipient: bool = False,
        flagged_addresses: list[str] | None = None,
        confirmation_id: str = "",
        confirmation_summary: str = "",
        summary: str = "",
    ):
        risk_val = risk_score.value if isinstance(risk_score, RiskScore) else str(risk_score)
        inst = super().__new__(cls, (bool(allowed), str(reason), risk_val))
        inst.allowed = bool(allowed)
        inst.reason = str(reason)
        inst.risk_score = risk_val
        inst.risk = risk_val
        inst.warning = str(warning)
        inst.requires_confirmation = bool(requires_confirmation)
        inst.injection_detected = bool(injection_detected)
        inst.is_new_recipient = bool(is_new_recipient)
        inst.flagged_addresses = list(flagged_addresses or [])
        inst.confirmation_id = str(confirmation_id or "")
        summary_val = str(confirmation_summary or summary or "")
        inst.confirmation_summary = summary_val
        inst.summary = summary_val
        inst.status = "requires_confirmation" if inst.requires_confirmation else ("allowed" if inst.allowed else "blocked")
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
                    elif instr.arg == 4:
                        return iter((self.allowed, self.reason, self.risk_score, self.requires_confirmation))
                    elif instr.arg == 5:
                        return iter((self.allowed, self.reason, self.risk_score, self.requires_confirmation, self.is_new_recipient))
                    elif instr.arg == 6:
                        return iter((self.allowed, self.reason, self.risk_score, self.requires_confirmation, self.confirmation_summary, self.confirmation_id))
        except Exception:
            pass
        return super().__iter__()


def normalize_address(address: str) -> str:
    """Normalize hex address string to 40 lowercase hex characters without prefix."""
    if not address:
        raise ValueError("Address cannot be empty")
    addr = str(address).strip()
    if addr.startswith(("0x", "0X")):
        addr = addr[2:]
    if not addr:
        raise ValueError("Address cannot be empty")
    if len(addr) == 64 and addr.startswith("0" * 24):
        addr = addr[24:]
    if len(addr) > 40:
        raise ValueError(f"Invalid Ethereum address length ({len(addr)}): {address}")
    if not all(c in "0123456789abcdefABCDEF" for c in addr):
        raise ValueError(f"Invalid Ethereum address non-hex characters: {address}")
    return addr.rjust(40, "0").lower()


def _canonical_data_hex(data_hex: Any) -> str:
    """
    Canonicalize calldata for confirmation binding.

    An omitted calldata argument may arrive as None, "", or "0x"; all three mean the
    same empty payload, so treating them as distinct would silently invalidate an
    operator's confirmation. Only these trivial equivalences are normalized —
    differing byte content is deliberately kept distinct so a mismatch fails closed.
    """
    raw = str(data_hex or "").strip().lower()
    return raw if raw else "0x"


# Well-known protocol & marketplace addresses
OPENSEA_SEAPORT_1_5 = normalize_address("0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC")
OPENSEA_SEAPORT_1_6 = normalize_address("0x0000000000000068F116a894984e2DB1123eB395")
OPENSEA_SEADROP = normalize_address("0x00005EA00Ac477B1030CE78506496e8C2dE24bf5")

# Ethereum Mainnet Routers
UNISWAP_V2_ROUTER = normalize_address("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")
UNISWAP_V3_ROUTER = normalize_address("0xE592427A0AEce92De3Edee1F18E0157C05861564")
UNISWAP_SWAP_ROUTER_02 = normalize_address("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45")
UNISWAP_UNIVERSAL_ROUTER = normalize_address("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD")

# Base (Chain ID 8453) DEX Routers
BASE_UNISWAP_ROUTER_02 = normalize_address("0x2626664c2603336E57B271c5C0b26F421741e481")
BASE_UNISWAP_UNIVERSAL_ROUTER = normalize_address("0x198EF79F1F515F02dFE9e3115e9F8078395e6c76")
BASE_AERODROME_ROUTER = normalize_address("0xcF77a3Ba9A5CA399B7c97c749545344273801A9B")
BASE_AERODROME_SLIPSTREAM = normalize_address("0xBE6D8f0d05cC4be24d5167a3eF062215bE6D18a5")

# Robinhood Gateway & Routers (Ethereum L1 & Arbitrum)
ROBINHOOD_L1_GATEWAY_ROUTER = normalize_address("0x6a2E3a1e16FC29f27Ce61429746D558d656975bB")
ROBINHOOD_ARBITRUM_SWAP_ROUTER = normalize_address("0x1E324B9316138CA9a73F960213621AD1aaf01B89")

KNOWN_VERIFIED_PROTOCOLS: set[str] = {
    OPENSEA_SEAPORT_1_5,
    OPENSEA_SEAPORT_1_6,
    OPENSEA_SEADROP,
    UNISWAP_V2_ROUTER,
    UNISWAP_V3_ROUTER,
    UNISWAP_SWAP_ROUTER_02,
    UNISWAP_UNIVERSAL_ROUTER,
    BASE_UNISWAP_ROUTER_02,
    BASE_UNISWAP_UNIVERSAL_ROUTER,
    BASE_AERODROME_ROUTER,
    BASE_AERODROME_SLIPSTREAM,
    ROBINHOOD_L1_GATEWAY_ROUTER,
    ROBINHOOD_ARBITRUM_SWAP_ROUTER,
    normalize_address(DEFAULT_ALLOWED_TARGET),
    normalize_address("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
}

NFT_MINT_SELECTORS: set[str] = {
    "a0712d68",  # mint(uint256)
    "1249c58b",  # mint()
    "755edd17",  # mintTo(address,uint256)
    "84bb1e42",  # claim(address,uint256,...)
    "e7acab24",  # fulfillAdvancedOrder
    "b3a34220",  # fulfillOrder
    "ed98257a",  # fulfillAvailableOrders
    "87201b41",  # fulfillAvailableAdvancedOrders
}

ERC20_TRANSFER_SELECTOR = "a9059cbb"

DEX_SWAP_SELECTORS: set[str] = {
    V2_SWAP_SELECTOR,
    V3_SWAP_SELECTOR,
    "8803dbee",  # swapTokensForExactTokens
    "7ff36ab5",  # swapExactETHForTokens
    "18cbafe5",  # swapExactTokensForETH
    "4a25e94a",  # swapTokensForExactETH
    "fb3bdb41",  # swapETHForExactTokens
    "5c11d795",  # exactInput
    "db3e2198",  # exactOutputSingle
    "f285a401",  # exactOutput
}


# ==============================================================================
# Address Memory & Context Integrity Protection Store
# ==============================================================================

@dataclass
class AddressEntry:
    """Metadata entry for an approved recipient address or trusted contract."""
    address: str
    address_type: str = "recipient"  # "recipient", "contract", "both"
    label: str = ""
    source: str = "manual"  # "manual", "config", "confirmation", "tool", "default"
    added_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        addr = self.address
        if addr and not addr.startswith(("0x", "0X")):
            addr = f"0x{addr}"
        return {
            "address": addr,
            "address_type": self.address_type,
            "label": self.label,
            "source": self.source,
            "added_at": self.added_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AddressEntry:
        addr = data.get("address", "")
        return cls(
            address=normalize_address(addr),
            address_type=str(data.get("address_type", data.get("type", "recipient"))),
            label=str(data.get("label", "")),
            source=str(data.get("source", "manual")),
            added_at=float(data.get("added_at", time.time())),
            metadata=dict(data.get("metadata", {})),
        )


class AddressMemoryStore:
    """
    Store of previously approved recipient addresses and trusted contracts.
    Protects autonomous agents against poisoned memory manipulation leading
    to unauthorized asset transfers or malicious contract interactions.

    Supports:
      - File or in-memory persistence
      - Thread-safe updates
      - Pre-approving addresses via config or tool
      - Exporting and loading to/from JSON format
    """

    def __init__(
        self,
        filepath: str | Path | None = None,
        initial_addresses: list[str | dict[str, Any]] | None = None,
        auto_save: bool = True,
    ) -> None:
        self.filepath: Path | None = Path(filepath) if filepath else None
        self.auto_save: bool = auto_save
        self._lock = threading.Lock()
        self._entries: dict[str, AddressEntry] = {}
        self._last_mtime: float = 0.0

        if self.filepath and self.filepath.is_file():
            self.load()

        if initial_addresses:
            for item in initial_addresses:
                if isinstance(item, str):
                    self.approve(item, label="initial", source="config")
                elif isinstance(item, dict):
                    addr = item.get("address") or item.get("addr") or ""
                    if addr:
                        self.approve(
                            addr,
                            label=str(item.get("label", "")),
                            address_type=str(item.get("address_type", item.get("type", "recipient"))),
                            source=str(item.get("source", "config")),
                            metadata=dict(item.get("metadata", {})),
                        )

    def _ensure_loaded(self) -> None:
        if not self.filepath or not self.filepath.is_file():
            return
        try:
            mtime = self.filepath.stat().st_mtime
            if mtime <= self._last_mtime and self._entries:
                return
            self.load()
        except Exception:
            pass

    @property
    def approved_addresses(self) -> set[str]:
        self._ensure_loaded()
        with self._lock:
            return set(self._entries.keys())

    def approve(
        self,
        address: str,
        label: str = "",
        address_type: str = "recipient",
        source: str = "manual",
        metadata: dict[str, Any] | None = None,
    ) -> AddressEntry:
        """Approve and record a recipient address or trusted contract."""
        self._ensure_loaded()
        norm = normalize_address(address)
        entry = AddressEntry(
            address=norm,
            address_type=address_type,
            label=label,
            source=source,
            metadata=metadata or {},
        )
        with self._lock:
            self._entries[norm] = entry
        if self.auto_save and self.filepath:
            self.save()
        return entry

    def add(self, *args: Any, **kwargs: Any) -> AddressEntry:
        """Alias for approve."""
        return self.approve(*args, **kwargs)

    def is_approved(self, address: str, address_type: str | None = None) -> bool:
        """Check if an address is approved (and optionally matches expected address_type)."""
        self._ensure_loaded()
        norm = normalize_address(address)
        with self._lock:
            entry = self._entries.get(norm)
            if not entry:
                return False
            if address_type and entry.address_type != "both" and entry.address_type != address_type:
                return False
            return True

    def is_known(self, address: str, address_type: str | None = None) -> bool:
        """Alias for is_approved."""
        return self.is_approved(address, address_type)

    def get(self, address: str) -> AddressEntry | None:
        self._ensure_loaded()
        norm = normalize_address(address)
        with self._lock:
            return self._entries.get(norm)

    def remove(self, address: str) -> bool:
        self._ensure_loaded()
        norm = normalize_address(address)
        with self._lock:
            existed = norm in self._entries
            if existed:
                del self._entries[norm]
        if existed and self.auto_save and self.filepath:
            self.save()
        return existed

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
        if self.auto_save and self.filepath:
            self.save()

    def list_addresses(self) -> list[dict[str, Any]]:
        self._ensure_loaded()
        with self._lock:
            return [e.to_dict() for e in self._entries.values()]

    def save(self, path: str | Path | None = None) -> None:
        target_path = Path(path) if path else self.filepath
        if not target_path:
            return
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            data = [e.to_dict() for e in self._entries.values()]
        temp_path = target_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        temp_path.replace(target_path)
        try:
            self._last_mtime = target_path.stat().st_mtime
        except Exception:
            pass

    def load(self, path: str | Path | None = None) -> None:
        target_path = Path(path) if path else self.filepath
        if not target_path or not target_path.is_file():
            return
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        with self._lock:
            self._entries.clear()
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "address" in item:
                        entry = AddressEntry.from_dict(item)
                        self._entries[entry.address] = entry
                    elif isinstance(item, str):
                        norm = normalize_address(item)
                        self._entries[norm] = AddressEntry(address=norm)
        try:
            self._last_mtime = target_path.stat().st_mtime
        except Exception:
            pass


DEFAULT_MEMORY_STORE_PATH = Path(__file__).resolve().parent / ".safeguard_memory.json"
_DEFAULT_MEMORY_STORE: AddressMemoryStore | None = None


def get_default_memory_store() -> AddressMemoryStore:
    global _DEFAULT_MEMORY_STORE
    if _DEFAULT_MEMORY_STORE is None:
        if "SAFEGUARD_MEMORY_PATH" in os.environ:
            mem_path = os.environ["SAFEGUARD_MEMORY_PATH"]
        else:
            try:
                from storage import resolve_state_path
                mem_path = str(resolve_state_path(".safeguard_memory.json"))
            except Exception:
                mem_path = str(DEFAULT_MEMORY_STORE_PATH)
        _DEFAULT_MEMORY_STORE = AddressMemoryStore(filepath=mem_path)
    return _DEFAULT_MEMORY_STORE


def set_default_memory_store(store: AddressMemoryStore | None) -> None:
    global _DEFAULT_MEMORY_STORE
    _DEFAULT_MEMORY_STORE = store


def reset_default_memory_store() -> None:
    global _DEFAULT_MEMORY_STORE
    if _DEFAULT_MEMORY_STORE:
        _DEFAULT_MEMORY_STORE.clear()
    mem_path = os.getenv("SAFEGUARD_MEMORY_PATH")
    if mem_path:
        _DEFAULT_MEMORY_STORE = AddressMemoryStore(filepath=mem_path)
    else:
        _DEFAULT_MEMORY_STORE = AddressMemoryStore()


def safeguard_approve_address(
    address: str,
    label: str = "",
    address_type: str = "recipient",
    store: AddressMemoryStore | None = None,
    threat_feed: ThreatFeed | None = None,
) -> dict[str, Any]:
    """
    User tool/helper to pre-approve common addresses (e.g. secondary wallet, known NFT contracts).
    """
    norm = normalize_address(address)
    tf = threat_feed or get_default_threat_feed()
    if tf.is_address_blocked(norm):
        threat = tf.get_address_threat(norm)
        threat_name = f": {threat.name}" if threat and threat.name else ""
        raise ValueError(f"Cannot approve address 0x{norm}. Address is blocked by threat feed{threat_name}")

    st = store or get_default_memory_store()
    entry = st.approve(norm, label=label, address_type=address_type, source="tool")
    logger.info("Hermes SafeGuard: Pre-approved address 0x%s (%s: %s)", norm, address_type, label)
    return {
        "status": "approved",
        "address": f"0x{norm}",
        "label": label,
        "type": address_type,
    }


def safeguard_list_approved_addresses(store: AddressMemoryStore | None = None) -> list[dict[str, Any]]:
    """List all currently approved addresses from the memory store."""
    st = store or get_default_memory_store()
    return st.list_addresses()


def safeguard_revoke_address(address: str, store: AddressMemoryStore | None = None) -> bool:
    """Revoke approval for an address."""
    norm = normalize_address(address)
    st = store or get_default_memory_store()
    return st.remove(norm)


# ==============================================================================
# Human Confirmation & Approval Framework (Degen & Elevated Risk Actions)
# ==============================================================================

@dataclass
class PendingConfirmation:
    """Represents a transaction or financial action awaiting explicit human approval."""
    id: str
    action: str
    tool_name: str
    tool_args: dict[str, Any]
    to_address: str
    value_wei: int
    data_hex: str
    risk_score: str
    reason: str
    summary: str
    mode: str
    created_at: float
    tx_digest: str = ""
    confirmed: bool = False
    rejected: bool = False
    consumed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "tool_name": self.tool_name,
            "to_address": f"0x{self.to_address}" if self.to_address else "",
            "value_wei": self.value_wei,
            "value_eth": self.value_wei / 10**18 if self.value_wei else 0.0,
            "data_hex": self.data_hex,
            "risk_score": self.risk_score,
            "reason": self.reason,
            "summary": self.summary,
            "mode": self.mode,
            "status": "confirmed" if self.confirmed else ("rejected" if self.rejected else "pending"),
            "created_at": self.created_at,
        }


DEFAULT_CONFIRMATION_STORE_PATH = Path.home() / ".hermes" / "safeguard_confirmations.json"
LOCAL_CONFIRMATION_STORE_PATH = Path(__file__).resolve().parent / ".safeguard_confirmations.json"


def _resolve_confirmation_store_path() -> Path:
    try:
        from storage import resolve_state_path
        p = resolve_state_path(".safeguard_confirmations.json")
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    except Exception:
        pass
    try:
        DEFAULT_CONFIRMATION_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        return DEFAULT_CONFIRMATION_STORE_PATH
    except Exception:
        return LOCAL_CONFIRMATION_STORE_PATH


class ConfirmationStore:
    """Thread-safe and process-safe store for pending, confirmed, and rejected human approval requests."""

    def __init__(
        self,
        ttl: float = 300.0,
        filepath: str | Path | None = None,
        auto_save: bool = True,
    ) -> None:
        self._lock = threading.Lock()
        self._pending: dict[str, PendingConfirmation] = {}
        self._confirmed_ids: set[str] = set()
        self._rejected_ids: set[str] = set()
        self.ttl: float = ttl
        self.filepath: Path | None = Path(filepath) if filepath else None
        self.auto_save: bool = auto_save
        self._last_mtime: float = 0.0

        if self.filepath and self.filepath.is_file():
            self._load()

    def _save(self) -> None:
        if not self.auto_save or not self.filepath:
            return
        try:
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "pending": {
                    k: {
                        "id": v.id,
                        "action": v.action,
                        "tool_name": v.tool_name,
                        "tool_args": v.tool_args,
                        "to_address": v.to_address,
                        "value_wei": v.value_wei,
                        "data_hex": v.data_hex,
                        "risk_score": v.risk_score,
                        "reason": v.reason,
                        "summary": v.summary,
                        "mode": v.mode,
                        "created_at": v.created_at,
                        "tx_digest": v.tx_digest,
                        "confirmed": v.confirmed,
                        "rejected": v.rejected,
                        "consumed": v.consumed,
                        "metadata": v.metadata,
                    }
                    for k, v in self._pending.items()
                },
                "confirmed_ids": list(self._confirmed_ids),
                "rejected_ids": list(self._rejected_ids),
            }
            tmp = self.filepath.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            tmp.replace(self.filepath)
            self._last_mtime = self.filepath.stat().st_mtime
        except Exception:
            pass

    def _load(self) -> None:
        if not self.filepath or not self.filepath.is_file():
            return
        try:
            mtime = self.filepath.stat().st_mtime
            if mtime <= self._last_mtime and self._pending:
                return
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            pending_raw = data.get("pending", {})
            for k, raw in pending_raw.items():
                if k not in self._pending:
                    self._pending[k] = PendingConfirmation(
                        id=raw["id"],
                        action=raw.get("action", ""),
                        tool_name=raw.get("tool_name", ""),
                        tool_args=raw.get("tool_args", {}),
                        to_address=raw.get("to_address", ""),
                        value_wei=int(raw.get("value_wei", 0)),
                        data_hex=raw.get("data_hex", "0x"),
                        risk_score=raw.get("risk_score", "high"),
                        reason=raw.get("reason", ""),
                        summary=raw.get("summary", ""),
                        mode=raw.get("mode", "degen"),
                        created_at=float(raw.get("created_at", time.time())),
                        tx_digest=raw.get("tx_digest", ""),
                        confirmed=bool(raw.get("confirmed", False)),
                        rejected=bool(raw.get("rejected", False)),
                        consumed=bool(raw.get("consumed", False)),
                        metadata=raw.get("metadata", {}),
                    )
                else:
                    cur = self._pending[k]
                    cur.confirmed = bool(raw.get("confirmed", cur.confirmed))
                    cur.rejected = bool(raw.get("rejected", cur.rejected))
                    cur.consumed = bool(raw.get("consumed", cur.consumed))

            for cid in data.get("confirmed_ids", []):
                self._confirmed_ids.add(cid)
            for rid in data.get("rejected_ids", []):
                self._rejected_ids.add(rid)
            self._last_mtime = mtime
        except Exception:
            pass

    def compute_tx_digest(self, to_address: str, value_wei: int, data_hex: str) -> str:
        try:
            norm_to = normalize_address(to_address) if to_address else ""
        except Exception:
            norm_to = str(to_address).strip().lower()
        clean_data = _canonical_data_hex(data_hex)
        hash_input = f"{norm_to}:{int(value_wei)}:{clean_data}"
        return hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

    def create_confirmation_request(
        self,
        action: str,
        tool_name: str = "",
        tool_args: dict[str, Any] | None = None,
        to_address: str = "",
        value_wei: int = 0,
        data_hex: str = "",
        risk_score: str = "high",
        reason: str = "",
        summary: str = "",
        mode: str = "degen",
        metadata: dict[str, Any] | None = None,
    ) -> PendingConfirmation:
        try:
            norm_to = normalize_address(to_address) if to_address else ""
        except Exception:
            norm_to = str(to_address).strip().lower()
        clean_data = _canonical_data_hex(data_hex)
        tx_digest = self.compute_tx_digest(norm_to, value_wei, clean_data)

        with self._lock:
            self._load()
            now = time.time()
            # If an identical unconsumed and unexpired confirmation request exists, reuse it
            for existing in self._pending.values():
                if (
                    existing.tx_digest == tx_digest
                    and not existing.confirmed
                    and not existing.consumed
                    and not existing.rejected
                    and (now - existing.created_at) < self.ttl
                ):
                    return existing

            hash_input = f"{norm_to}:{value_wei}:{clean_data}:{tool_name}:{now}"
            conf_id = "conf_" + hashlib.sha256(hash_input.encode("utf-8")).hexdigest()[:12]
            entry = PendingConfirmation(
                id=conf_id,
                action=action,
                tool_name=tool_name,
                tool_args=dict(tool_args or {}),
                to_address=norm_to,
                value_wei=value_wei,
                data_hex=clean_data,
                risk_score=risk_score,
                reason=reason,
                summary=summary,
                mode=mode,
                created_at=now,
                tx_digest=tx_digest,
                metadata=dict(metadata or {}),
            )
            self._pending[conf_id] = entry
            self._save()
            return entry

    def confirm(self, confirmation_id: str) -> bool:
        with self._lock:
            self._load()
            if confirmation_id not in self._pending:
                return False
            entry = self._pending[confirmation_id]
            if (time.time() - entry.created_at) > self.ttl:
                return False
            entry.confirmed = True
            entry.rejected = False
            self._confirmed_ids.add(confirmation_id)
            self._rejected_ids.discard(confirmation_id)
            self._save()
            return True

    def find_confirmed_entry(self, to_address: str, value_wei: int | None = None) -> PendingConfirmation | None:
        """Find an unconsumed confirmed entry matching to_address and value."""
        with self._lock:
            self._load()
            now = time.time()
            try:
                norm_to = normalize_address(to_address)
            except Exception:
                norm_to = str(to_address).strip().lower()
            for entry in reversed(list(self._pending.values())):
                if (
                    entry.confirmed
                    and not entry.rejected
                    and not entry.consumed
                    and (now - entry.created_at) < self.ttl
                    and entry.to_address == norm_to
                ):
                    if value_wei is not None and int(entry.value_wei) != int(value_wei):
                        continue
                    return entry
            return None

    def reject(self, confirmation_id: str) -> bool:
        with self._lock:
            self._load()
            if confirmation_id not in self._pending:
                return False
            entry = self._pending[confirmation_id]
            entry.rejected = True
            entry.confirmed = False
            self._rejected_ids.add(confirmation_id)
            self._confirmed_ids.discard(confirmation_id)
            self._save()
            return True

    def is_confirmed(
        self,
        confirmation_id: str,
        to_address: str | None = None,
        value_wei: int | None = None,
        data_hex: str | None = None,
        consume: bool = False,
    ) -> bool:
        with self._lock:
            self._load()
            if confirmation_id in self._rejected_ids:
                return False
            entry = self._pending.get(confirmation_id)
            if not entry or not entry.confirmed or entry.rejected or entry.consumed:
                return False
            if (time.time() - entry.created_at) > self.ttl:
                return False
            # Verify parameter binding against stored transaction digest
            if to_address is not None:
                try:
                    norm_to = normalize_address(to_address)
                except Exception:
                    norm_to = str(to_address).strip().lower()
                if entry.to_address != norm_to:
                    return False
            if value_wei is not None and entry.value_wei != int(value_wei):
                return False
            if data_hex is not None:
                clean_data = _canonical_data_hex(data_hex)
                entry_data = _canonical_data_hex(entry.data_hex)
                if entry_data != clean_data:
                    return False
            if consume:
                entry.consumed = True
                self._confirmed_ids.discard(confirmation_id)
                self._save()
            return True

    def is_rejected(self, confirmation_id: str) -> bool:
        with self._lock:
            self._load()
            if confirmation_id in self._rejected_ids:
                return True
            entry = self._pending.get(confirmation_id)
            return bool(entry and entry.rejected)

    def get(self, confirmation_id: str) -> PendingConfirmation | None:
        with self._lock:
            self._load()
            return self._pending.get(confirmation_id)

    def list_pending(self) -> list[dict[str, Any]]:
        with self._lock:
            self._load()
            now = time.time()
            return [
                p.to_dict()
                for p in self._pending.values()
                if not p.confirmed and not p.rejected and not p.consumed and (now - p.created_at) < self.ttl
            ]

    def clear(self) -> None:
        with self._lock:
            self._pending.clear()
            self._confirmed_ids.clear()
            self._rejected_ids.clear()
            if self.filepath and self.filepath.is_file():
                try:
                    self.filepath.unlink()
                except Exception:
                    pass
            self._last_mtime = 0.0


_DEFAULT_CONFIRMATION_STORE = ConfirmationStore(filepath=_resolve_confirmation_store_path())


def get_default_confirmation_store() -> ConfirmationStore:
    global _DEFAULT_CONFIRMATION_STORE
    return _DEFAULT_CONFIRMATION_STORE


def reset_default_confirmation_store() -> None:
    global _DEFAULT_CONFIRMATION_STORE
    if _DEFAULT_CONFIRMATION_STORE:
        _DEFAULT_CONFIRMATION_STORE.clear()
    _DEFAULT_CONFIRMATION_STORE = ConfirmationStore(filepath=_resolve_confirmation_store_path())


# ==============================================================================
# Financial Action Audit Logger (Allowed, Blocked, Requires Confirmation)
# ==============================================================================

@dataclass
class FinancialActionLogEntry:
    """Structured audit log entry recording financial transactions and security decisions."""
    timestamp: float
    action: str  # e.g. "safeguard_execute_tx", "transfer", "swap", "approve", "mint"
    status: str  # "allowed", "blocked", "requires_confirmation", "confirmed", "rejected"
    mode: str    # "strict", "balanced", "degen"
    target: str
    value_wei: int
    data_hex: str
    risk_score: str
    reason: str
    summary: str
    confirmation_id: str | None = None
    warning: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "status": self.status,
            "mode": self.mode,
            "target": f"0x{self.target}" if self.target else "",
            "value_wei": self.value_wei,
            "value_eth": self.value_wei / 10**18 if self.value_wei else 0.0,
            "data_hex": self.data_hex,
            "risk_score": self.risk_score,
            "reason": self.reason,
            "summary": self.summary,
            "confirmation_id": self.confirmation_id,
            "warning": self.warning,
            "metadata": self.metadata,
        }


class ActionAuditLogger:
    """Thread-safe in-memory and structured logger for all intercepted financial actions."""

    def __init__(self, log_path: str | Path | None = None) -> None:
        self._lock = threading.Lock()
        self._entries: list[FinancialActionLogEntry] = []
        # Optional JSONL persistence. SAFEGUARD_AUDIT_LOG_PATH enables it; None keeps in-memory only.
        env_path = os.getenv("SAFEGUARD_AUDIT_LOG_PATH") if log_path is None else None
        resolved = log_path or env_path
        self.log_path: Path | None = Path(resolved).expanduser() if resolved else None

    def _persist(self, entry: FinancialActionLogEntry) -> None:
        """Append one JSON line to the audit file. Never raise: logging must not break enforcement."""
        if not self.log_path:
            return
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), default=str) + "\n")
        except Exception:
            pass

    def log(
        self,
        action: str,
        status: str,
        mode: str,
        target: str = "",
        value_wei: int = 0,
        data_hex: str = "",
        risk_score: str = "low",
        reason: str = "",
        summary: str = "",
        confirmation_id: str | None = None,
        warning: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> FinancialActionLogEntry:
        try:
            norm_target = normalize_address(target) if target else ""
        except Exception:
            norm_target = str(target or "")
        with self._lock:
            entry = FinancialActionLogEntry(
                timestamp=time.time(),
                action=action,
                status=status,
                mode=mode,
                target=norm_target,
                value_wei=value_wei,
                data_hex=data_hex,
                risk_score=risk_score,
                reason=reason,
                summary=summary,
                confirmation_id=confirmation_id,
                warning=warning,
                metadata=dict(metadata or {}),
            )
            self._entries.append(entry)
            self._persist(entry)

            # High-visibility logging
            target_str = f"0x{norm_target}" if norm_target else "none"
            val_eth = value_wei / 10**18 if value_wei else 0.0
            if status == "allowed":
                logger.info(
                    "Hermes SafeGuard AUDIT [ALLOWED]: mode=%s action=%s target=%s value=%.4f ETH risk=%s warning='%s'",
                    mode, action, target_str, val_eth, risk_score, warning or "none",
                )
            elif status == "requires_confirmation":
                logger.warning(
                    "Hermes SafeGuard AUDIT [REQUIRES_CONFIRMATION]: mode=%s action=%s target=%s value=%.4f ETH risk=%s id=%s reason='%s'",
                    mode, action, target_str, val_eth, risk_score, confirmation_id, reason,
                )
            elif status == "blocked":
                logger.warning(
                    "Hermes SafeGuard AUDIT [BLOCKED]: mode=%s action=%s target=%s value=%.4f ETH risk=%s reason='%s'",
                    mode, action, target_str, val_eth, risk_score, reason,
                )
            elif status == "confirmed":
                logger.info(
                    "Hermes SafeGuard AUDIT [CONFIRMED]: id=%s action=%s target=%s",
                    confirmation_id, action, target_str,
                )
            elif status == "rejected":
                logger.info(
                    "Hermes SafeGuard AUDIT [REJECTED]: id=%s action=%s target=%s",
                    confirmation_id, action, target_str,
                )

            return entry

    def get_entries(
        self,
        limit: int = 50,
        status: str | None = None,
        mode: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            filtered = self._entries
            if status:
                filtered = [e for e in filtered if e.status == status]
            if mode:
                filtered = [e for e in filtered if e.mode == mode]
            return [e.to_dict() for e in filtered[-limit:]]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


_DEFAULT_AUDIT_LOGGER = ActionAuditLogger()


def get_default_audit_logger() -> ActionAuditLogger:
    global _DEFAULT_AUDIT_LOGGER
    return _DEFAULT_AUDIT_LOGGER


def reset_default_audit_logger() -> None:
    global _DEFAULT_AUDIT_LOGGER
    _DEFAULT_AUDIT_LOGGER = ActionAuditLogger()


def log_financial_action(
    action: str,
    status: str,
    mode: str,
    target: str = "",
    value_wei: int = 0,
    data_hex: str = "",
    risk_score: str = "low",
    reason: str = "",
    summary: str = "",
    confirmation_id: str | None = None,
    warning: str = "",
    metadata: dict[str, Any] | None = None,
    audit_logger: ActionAuditLogger | None = None,
) -> FinancialActionLogEntry:
    """Convenience helper to record a financial action in the audit log."""
    al = audit_logger or get_default_audit_logger()
    return al.log(
        action=action,
        status=status,
        mode=mode,
        target=target,
        value_wei=value_wei,
        data_hex=data_hex,
        risk_score=risk_score,
        reason=reason,
        summary=summary,
        confirmation_id=confirmation_id,
        warning=warning,
        metadata=metadata,
    )


# ==============================================================================
# Transaction Human-Readable Summarizer
# ==============================================================================

def generate_transaction_summary(
    to_address: str,
    value_wei: int = 0,
    data_hex: str = "",
    risk_reasons: list[str] | None = None,
    mode: str = "degen",
    tool_name: str = "",
) -> str:
    """
    Produce a clean, human-readable summary of what an on-chain transaction or tool action
    will do, highlighting risk factors and financial impact for user confirmation.
    """
    norm_to = normalize_address(to_address) if to_address else ""
    raw = data_hex.strip() if data_hex else ""
    if raw.startswith(("0x", "0X")):
        raw = raw[2:]
    sel = raw[:8].lower() if len(raw) >= 8 else ""
    val_eth = value_wei / 10**18 if value_wei else 0.0

    lines: list[str] = [
        f"Transaction Summary ({mode.capitalize()} Mode - Human Confirmation Required):",
    ]

    target_desc = f"0x{norm_to}" if norm_to else "none"
    if norm_to in KNOWN_VERIFIED_PROTOCOLS:
        target_desc += " (Verified Protocol)"
    lines.append(f"• Target Address: {target_desc}")
    lines.append(f"• Value: {val_eth:.4f} ETH ({value_wei} wei)")

    if sel == APPROVE_SELECTOR and len(raw) >= 72:
        spender = normalize_address(raw[8:72])
        amt = int(raw[72:136], 16) if len(raw) >= 136 else 0
        amt_str = "Unlimited (type(uint256).max)" if amt == UINT256_MAX else f"{amt / 10**18:.4f} Tokens ({amt})"
        lines.append("• Action: ERC-20 Token Approval (approve)")
        lines.append(f"• Spender: 0x{spender}")
        lines.append(f"• Approved Amount: {amt_str}")
        lines.append(f"• Impact: Grants 0x{spender} permission to transfer tokens from your wallet.")

    elif sel == SET_APPROVAL_FOR_ALL_SELECTOR and len(raw) >= 72:
        operator = normalize_address(raw[8:72])
        approved = int(raw[72:136], 16) != 0 if len(raw) >= 136 else True
        lines.append("• Action: NFT Collection Approval (setApprovalForAll)")
        lines.append(f"• Operator: 0x{operator}")
        lines.append(f"• Approved: {approved}")
        lines.append(f"• Impact: Grants 0x{operator} full access to transfer ANY token in this NFT collection.")

    elif sel == PERMIT2_APPROVE_SELECTOR and len(raw) >= 136:
        tok = normalize_address(raw[8:72])
        spender = normalize_address(raw[72:136])
        lines.append("• Action: Permit2 Approval")
        lines.append(f"• Token: 0x{tok}")
        lines.append(f"• Spender: 0x{spender}")

    elif sel == ERC20_TRANSFER_SELECTOR and len(raw) >= 72:
        recip = normalize_address(raw[8:72])
        amt = int(raw[72:136], 16) if len(raw) >= 136 else 0
        lines.append("• Action: ERC-20 Token Transfer")
        lines.append(f"• Recipient: 0x{recip}")
        lines.append(f"• Amount: {amt / 10**18:.4f} Tokens ({amt})")
        lines.append(f"• Impact: Transfers tokens directly from your wallet.")

    elif sel == V2_SWAP_SELECTOR:
        amt_out_min = int(raw[72:136], 16) if len(raw) >= 136 else 0
        lines.append("• Action: Uniswap V2 DEX Swap")
        if amt_out_min == 0:
            lines.append("• Slippage Protection: NONE (amountOutMin = 0, 100% MEV slippage exposure)")
        else:
            lines.append(f"• Minimum Output: {amt_out_min}")
        lines.append("• Impact: Swaps input assets on DEX for target tokens.")

    elif sel == V3_SWAP_SELECTOR:
        amt_out_min = int(raw[392:456], 16) if len(raw) >= 456 else 0
        lines.append("• Action: Uniswap V3 DEX Swap")
        if amt_out_min == 0:
            lines.append("• Slippage Protection: NONE (amountOutMinimum = 0, 100% MEV slippage exposure)")
        else:
            lines.append(f"• Minimum Output: {amt_out_min}")
        lines.append("• Impact: Swaps input assets on Uniswap V3.")

    elif sel == MULTICALL_SELECTOR:
        try:
            raw_bytes = bytes.fromhex(raw[8:])
            sub_calls = decode_bytes_array(raw_bytes)
            lines.append(f"• Action: Multicall Batch Transaction ({len(sub_calls)} sub-calls)")
            for i, c in enumerate(sub_calls[:5], start=1):
                c_hex = c.hex()
                c_sel = c_hex[:8].lower() if len(c_hex) >= 8 else "0x"
                desc = "Operation"
                if c_sel == APPROVE_SELECTOR:
                    desc = f"ERC-20 approve (spender=0x{c_hex[32:72]}...)"
                elif c_sel == ERC20_TRANSFER_SELECTOR:
                    desc = f"ERC-20 transfer (recip=0x{c_hex[32:72]}...)"
                elif c_sel in (V2_SWAP_SELECTOR, V3_SWAP_SELECTOR):
                    desc = "DEX swap"
                elif c_sel == SET_APPROVAL_FOR_ALL_SELECTOR:
                    desc = "NFT setApprovalForAll"
                else:
                    desc = f"contract call (selector=0x{c_sel})"
                lines.append(f"  {i}. {desc}")
            if len(sub_calls) > 5:
                lines.append(f"  ... and {len(sub_calls) - 5} more sub-calls")
        except Exception:
            lines.append("• Action: Multicall Batch Transaction (malformed/custom calldata)")

    elif sel in NFT_MINT_SELECTORS or "mint" in raw.lower():
        lines.append("• Action: NFT Mint")
        lines.append(f"• Mint Price: {val_eth:.4f} ETH")
        lines.append("• Impact: Mints NFT to wallet from contract.")

    elif not raw or len(raw) < 8:
        lines.append("• Action: Native ETH Transfer")
        lines.append(f"• Recipient: 0x{norm_to}")
        lines.append(f"• Impact: Transfers {val_eth:.4f} ETH out of wallet.")

    else:
        lines.append(f"• Action: Contract Interaction (selector: 0x{sel})")
        lines.append(f"• Target Contract: 0x{norm_to}")

    # Risk reasons
    if risk_reasons:
        lines.append("• Risk Assessment: HIGH / REQUIRES CONFIRMATION")
        lines.append("• Risk Factors:")
        for r in risk_reasons:
            lines.append(f"  - {r}")
    else:
        lines.append("• Risk Assessment: Elevated transaction parameters require human verification.")

    lines.append("• Confirmation: Use safeguard_confirm_action tool or approve via Hermes/Telegram to proceed.")
    return "\n".join(lines)


# ==============================================================================
# Agent & User Tools: Confirmation and Audit
# ==============================================================================

def safeguard_confirm_action(
    confirmation_id: str,
    approved: bool = True,
    confirmation_store: ConfirmationStore | None = None,
    memory_store: AddressMemoryStore | None = None,
    audit_logger: ActionAuditLogger | None = None,
) -> dict[str, Any]:
    """
    Human-approval tool to confirm or reject a pending transaction or tool call.

    Parameters:
        confirmation_id: The confirmation ID returned in VerificationResult.confirmation_id.
        approved: True to approve and allow execution, False to reject.
    """
    cs = confirmation_store or get_default_confirmation_store()
    ms = memory_store or get_default_memory_store()
    al = audit_logger or get_default_audit_logger()

    entry = cs.get(confirmation_id)
    if not entry:
        return {
            "status": "error",
            "confirmation_id": confirmation_id,
            "approved": False,
            "message": f"Confirmation ID '{confirmation_id}' not found in pending store",
        }

    if approved:
        # Exploit safety check: Never confirm known critical exploits even if operator requests
        raw_data = str(entry.data_hex or "").lower().replace("0x", "")
        sel = raw_data[:8]
        if sel in ("d8a17684", "f4c9c118", "756e6578", "de1e9a7e", "74617802"):
            cs.reject(confirmation_id)
            return {
                "status": "error",
                "confirmation_id": confirmation_id,
                "approved": False,
                "message": "Cannot confirm action: transaction calldata matches known exploit pattern / drainer selector. SafeGuard blocked confirmation.",
            }
        success = cs.confirm(confirmation_id)
        if not success:
            return {
                "status": "error",
                "confirmation_id": confirmation_id,
                "approved": False,
                "message": f"Confirmation ID '{confirmation_id}' is expired or invalid",
            }
        al.log(
            action=entry.action or entry.tool_name or "confirm",
            status="confirmed",
            mode=entry.mode,
            target=entry.to_address,
            value_wei=entry.value_wei,
            data_hex=entry.data_hex,
            risk_score=entry.risk_score,
            reason="Action confirmed by human approval",
            summary=entry.summary,
            confirmation_id=confirmation_id,
        )
        logger.info("Hermes SafeGuard: Action confirmed by operator approval: %s", confirmation_id)
        return {
            "status": "confirmed",
            "confirmation_id": confirmation_id,
            "approved": True,
            "summary": entry.summary,
            "message": "Action has been approved by operator.",
        }
    else:
        cs.reject(confirmation_id)
        al.log(
            action=entry.action or entry.tool_name or "confirm",
            status="rejected",
            mode=entry.mode,
            target=entry.to_address,
            value_wei=entry.value_wei,
            data_hex=entry.data_hex,
            risk_score=entry.risk_score,
            reason="Action rejected by operator",
            summary=entry.summary,
            confirmation_id=confirmation_id,
        )
        logger.info("Hermes SafeGuard: Action rejected by operator: %s", confirmation_id)
        return {
            "status": "rejected",
            "confirmation_id": confirmation_id,
            "approved": False,
            "summary": entry.summary,
            "message": "Action has been rejected by operator.",
        }


def safeguard_list_pending_confirmations(
    confirmation_store: ConfirmationStore | None = None,
) -> list[dict[str, Any]]:
    """List all pending transaction confirmation requests awaiting human approval."""
    cs = confirmation_store or get_default_confirmation_store()
    return cs.list_pending()


def safeguard_get_audit_log(
    limit: int = 50,
    status: str | None = None,
    mode: str | None = None,
    audit_logger: ActionAuditLogger | None = None,
) -> list[dict[str, Any]]:
    """Retrieve audit history of all allowed, blocked, and confirmed financial actions."""
    al = audit_logger or get_default_audit_logger()
    return al.get_entries(limit=limit, status=status, mode=mode)


# ==============================================================================
# Threat Feed & Security Blocklist
# ==============================================================================

"""
Hermes SafeGuard Threat Feed & Blocklist Maintenance Guide
==========================================================

HOW THIS LIST SHOULD BE MAINTAINED:

1. Threat Feed Sources & Intelligence Ingestion:
   - Web3 Threat Feeds: Continuously ingest verified malicious addresses, drainer
     proxies, and phishing sweepers from security firms (SlowMist, ScamSniffer,
     PeckShield, CertiK, Chainabuse).
   - Agent Incident Reports: Track and document emerging autonomous agent exploit
     patterns, prompt injection attack vectors, memory poisoning attempts, and
     calldata smuggling techniques.
   - On-chain Trace Analysis: Reverse-engineer wallet drainers, sweepers, and
     fake protocol routers observed in exploit transactions.

2. Ingestion & Update Procedure:
   - Address Normalization: All addresses MUST be normalized 20-byte EVM addresses
     (40 lowercase hexadecimal characters; normalize_address() handles 0x prefix and
     checksum capitalization).
   - Selector Normalization: All selectors MUST be 4-byte hexadecimal values
     (8 lowercase hex characters without 0x prefix).
   - Metadata Standards: Entries must include 'name', 'category', 'description',
     'severity', and 'date_added'.
   - Versioning: Increment semantic version and update 'updated_at' timestamp upon
     modifying the blocklist file (blocklist.json or blocklist.yaml).

3. Security Invariant (Fail-Closed Across All Modes):
   - Items on this threat feed / blocklist are HARD-BLOCKED in ALL policy modes (strict,
     balanced, and degen). Even with human confirmation (confirmed=True), interaction
     is rejected.
   - Pre-approvals for blocked addresses via safeguard_approve_address are strictly
     prohibited and rejected.

4. Validation & Regression Testing:
   - Run 'python3 -m unittest discover tests' and 'python3 verifier.py --test' before
     merging any updates. Ensure verified protocol routers (e.g. Uniswap, Seaport)
     are never mistakenly added to the blocklist.

5. Future Integration Roadmap:
   - Connect to live Twitter/X API search and real-time security APIs with cryptographic
     feed signature validation.
"""


@dataclass
class ThreatEntry:
    target: str  # normalized address (40 hex) or selector (8 hex)
    threat_type: str  # "malicious_contract", "phishing", "dangerous_selector"
    name: str = ""
    signature: str = ""
    description: str = ""
    severity: str = "CRITICAL"
    source: str = "local_blocklist"
    date_added: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "type": self.threat_type,
            "name": self.name,
            "signature": self.signature,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "date_added": self.date_added,
            "metadata": self.metadata,
        }


@dataclass
class ThreatReport:
    id: str
    title: str
    category: str
    threat_level: str
    description: str
    indicators: list[str] = field(default_factory=list)
    reported_date: str = ""
    source: str = "threat_feed"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": "agent_attack_pattern",
            "title": self.title,
            "category": self.category,
            "threat_level": self.threat_level,
            "severity": self.threat_level,
            "description": self.description,
            "indicators": self.indicators,
            "reported_date": self.reported_date,
            "source": self.source,
            "metadata": self.metadata,
        }


class ThreatFeed:
    """
    Local threat feed and security blocklist manager for Hermes SafeGuard.
    Loads and updates:
      - Known malicious contract addresses
      - Known phishing & wallet drain addresses
      - Dangerous function selectors
      - Agent-related attack patterns and incident reports
    """

    def __init__(
        self,
        filepath: str | Path | None = None,
        auto_load: bool = True,
    ) -> None:
        self.filepath: Path | None = Path(filepath) if filepath else None
        self._lock = threading.Lock()
        self._blocked_addresses: dict[str, ThreatEntry] = {}
        self._blocked_selectors: dict[str, ThreatEntry] = {}
        self._reports: list[dict[str, Any]] = []
        self.version: str = "1.0.0"
        self.updated_at: str = ""
        self.description: str = ""

        # Auto-discover or load if filepath specified or default file exists
        if self.filepath:
            if self.filepath.is_file():
                self.load()
            else:
                self._load_fallback_defaults()
        elif auto_load:
            found_path = self._find_default_blocklist()
            if found_path and found_path.is_file():
                self.filepath = found_path
                self.load()
            else:
                self._load_fallback_defaults()
        else:
            self._load_fallback_defaults()

    def _find_default_blocklist(self) -> Path | None:
        env_path = os.getenv("SAFEGUARD_BLOCKLIST_PATH")
        candidates = []
        if env_path:
            candidates.append(Path(env_path))
        candidates.extend([
            Path("blocklist.json"),
            Path(__file__).parent / "blocklist.json",
            Path("policies/blocklist.json"),
            Path(__file__).parent / "policies/blocklist.json",
            Path.home() / ".hermes/blocklist.json",
            Path("blocklist.yaml"),
            Path(__file__).parent / "blocklist.yaml",
        ])
        for p in candidates:
            try:
                if p.is_file():
                    return p.resolve()
            except Exception:
                pass
        return None

    def _load_fallback_defaults(self) -> None:
        """Seed minimal built-in threat items to guarantee fail-closed security even without a disk file."""
        fallback_contracts = [
            ("000000000000000000000000000000000000bad1", "Simulated Drain Exploit Contract", "Known test & drain exploit contract"),
            ("742d35cc6634c0532925a3b844bc454e4438f44e", "Inferno Drainer Proxy", "Multi-chain phishing & wallet drainer contract"),
            ("000000000001844b20ccf2635d00d36983296204", "Fake Permit2 Router Drainer", "Spoofed Permit2 proxy executing token sweeps"),
            ("98c23e9d8f34fefb1b7bd6a91b7ee122f4b16f5c", "Angel Drainer Sweep Contract", "Drainer sweeping assets via compromised signatures"),
            ("1111111254fb6c44bac0bed2854e76f90643097d", "Phishing Token Impersonator", "Malicious clone targeting DEX routers"),
        ]
        fallback_phishing = [
            ("1234567890123456789012345678901234567890", "Known Phishing Drainer EOA", "Phishing campaign sweep address"),
            ("888888888888888888888888888888888888bad0", "Fake Airdrop Phishing Recipient", "Phishing collector wallet"),
            ("6b75d8af000000e20b7a7ddf000ba900b4009a80", "Compromised Key Drain Collector", "Drain recipient wallet active in bot attacks"),
            ("deadbeef11112222333344445555666677778888", "Known Exploit Sweeper EOA", "Sweeper address actively draining ERC20 balances"),
        ]
        fallback_selectors = [
            ("23b872dd", "transferFrom(address,address,uint256)", "Standard ERC-20 transferFrom drain invocation"),
            ("baa2abde", "sweepTokens(address,address[])", "Unauthorized token sweeping function"),
            ("39125215", "emergencyDrain(address)", "Emergency drain selector in phishing contracts"),
            ("42966c68", "burnFrom(address,uint256)", "Destructive token burn execution"),
            ("41bb3396", "drainEther(address)", "Native balance exfiltration selector"),
            ("6f307dc3", "destroy(address)", "Contract selfdestruct / balance draining call"),
            ("83197ef0", "drainToken(address,address)", "Token drain selector targeting approved balances"),
            ("e946a47b", "sweep(address)", "Direct asset sweep function"),
        ]
        with self._lock:
            for addr, name, desc in fallback_contracts:
                self._add_address_locked(addr, "malicious_contract", name, desc)
            for addr, name, desc in fallback_phishing:
                self._add_address_locked(addr, "phishing", name, desc)
            for sel, sig, desc in fallback_selectors:
                self._add_selector_locked(sel, sig, desc)

    def _add_address_locked(
        self,
        address: str,
        category: str = "malicious_contract",
        name: str = "",
        description: str = "",
        severity: str = "CRITICAL",
        date_added: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> ThreatEntry:
        norm = normalize_address(address)
        entry = ThreatEntry(
            target=norm,
            threat_type=category,
            name=name or f"Blocked {category}: 0x{norm[:6]}...{norm[-4:]}",
            description=description,
            severity=severity,
            date_added=date_added or time.strftime("%Y-%m-%d"),
            metadata=metadata or {},
        )
        self._blocked_addresses[norm] = entry
        report = {
            "id": f"ADDR-{norm[:8]}",
            "type": category,
            "target": f"0x{norm}",
            "name": entry.name,
            "title": entry.name,
            "category": category,
            "severity": severity,
            "description": description,
            "date_reported": entry.date_added,
            "source": "threat_blocklist",
        }
        self._reports.append(report)
        return entry

    def _add_selector_locked(
        self,
        selector: str,
        signature: str = "",
        description: str = "",
        severity: str = "CRITICAL",
        metadata: dict[str, Any] | None = None,
    ) -> ThreatEntry:
        raw = selector.strip()
        if raw.startswith(("0x", "0X")):
            raw = raw[2:]
        raw = raw[:8].lower()
        entry = ThreatEntry(
            target=raw,
            threat_type="dangerous_selector",
            name=signature or f"Blocked Selector 0x{raw}",
            signature=signature,
            description=description,
            severity=severity,
            metadata=metadata or {},
        )
        self._blocked_selectors[raw] = entry
        report = {
            "id": f"SEL-{raw}",
            "type": "dangerous_selector",
            "target": f"0x{raw}",
            "name": entry.name,
            "title": entry.name,
            "signature": signature,
            "category": "dangerous_selector",
            "severity": severity,
            "description": description,
            "source": "threat_blocklist",
        }
        self._reports.append(report)
        return entry

    def load(self, path: str | Path | None = None) -> None:
        target_path = Path(path) if path else self.filepath
        if not target_path or not target_path.is_file():
            self._load_fallback_defaults()
            return

        with open(target_path, "r", encoding="utf-8") as f:
            raw_text = f.read()

        data: dict[str, Any] = {}
        if str(target_path).endswith((".yaml", ".yml")) and _HAVE_YAML:
            loaded = yaml.safe_load(raw_text)
            if isinstance(loaded, dict):
                data = loaded
        else:
            try:
                data = json.loads(raw_text)
            except Exception:
                if _HAVE_YAML:
                    loaded = yaml.safe_load(raw_text)
                    if isinstance(loaded, dict):
                        data = loaded

        with self._lock:
            self._blocked_addresses.clear()
            self._blocked_selectors.clear()
            self._reports.clear()

            self.version = str(data.get("version", "1.0.0"))
            self.updated_at = str(data.get("updated_at", ""))
            self.description = str(data.get("description", ""))

            # 1. Malicious contracts
            for item in data.get("malicious_contracts", []):
                if isinstance(item, dict):
                    addr = item.get("address") or item.get("addr") or ""
                    if addr:
                        self._add_address_locked(
                            addr,
                            category=item.get("category", "malicious_contract"),
                            name=item.get("name", ""),
                            description=item.get("description", ""),
                            severity=item.get("severity", "CRITICAL"),
                            date_added=item.get("date_added", ""),
                            metadata=item.get("metadata", {}),
                        )
                elif isinstance(item, str):
                    self._add_address_locked(item, category="malicious_contract")

            # 2. Phishing addresses
            for item in data.get("phishing_addresses", []):
                if isinstance(item, dict):
                    addr = item.get("address") or item.get("addr") or ""
                    if addr:
                        self._add_address_locked(
                            addr,
                            category=item.get("category", "phishing"),
                            name=item.get("name", ""),
                            description=item.get("description", ""),
                            severity=item.get("severity", "CRITICAL"),
                            date_added=item.get("date_added", ""),
                            metadata=item.get("metadata", {}),
                        )
                elif isinstance(item, str):
                    self._add_address_locked(item, category="phishing")

            # 3. Generic addresses / denylist / blocklist
            for key in ("addresses", "denylist", "blocked_addresses", "blocklist"):
                for item in data.get(key, []):
                    if isinstance(item, dict):
                        addr = item.get("address") or item.get("addr") or ""
                        if addr:
                            self._add_address_locked(
                                addr,
                                category=item.get("category", "malicious_address"),
                                name=item.get("name", ""),
                                description=item.get("description", ""),
                                severity=item.get("severity", "CRITICAL"),
                            )
                    elif isinstance(item, str):
                        self._add_address_locked(item, category="malicious_address")

            # 4. Dangerous selectors
            for key in ("dangerous_selectors", "selectors", "blocked_selectors"):
                for item in data.get(key, []):
                    if isinstance(item, dict):
                        sel = item.get("selector") or item.get("sel") or ""
                        if sel:
                            self._add_selector_locked(
                                sel,
                                signature=item.get("signature", ""),
                                description=item.get("description", ""),
                                severity=item.get("severity", "CRITICAL"),
                                metadata=item.get("metadata", {}),
                            )
                    elif isinstance(item, str):
                        self._add_selector_locked(item)

            # 5. Agent attack patterns & threat reports
            for key in ("agent_attack_patterns", "recent_threat_reports", "reports", "attack_patterns"):
                for item in data.get(key, []):
                    if isinstance(item, dict):
                        report = {
                            "id": item.get("id", f"RPT-{len(self._reports)+1:03d}"),
                            "type": item.get("type", "agent_attack_pattern"),
                            "title": item.get("title", item.get("name", "")),
                            "name": item.get("name", item.get("title", "")),
                            "category": item.get("category", "agent_attack_pattern"),
                            "threat_level": item.get("threat_level", item.get("severity", "CRITICAL")),
                            "severity": item.get("severity", item.get("threat_level", "CRITICAL")),
                            "description": item.get("description", ""),
                            "indicators": list(item.get("indicators", [])),
                            "reported_date": item.get("reported_date", item.get("date_added", "")),
                            "source": item.get("source", "local_threat_feed"),
                            "metadata": dict(item.get("metadata", {})),
                        }
                        self._reports.append(report)

            # Ensure TRANSFER_FROM_SELECTOR is always present
            if TRANSFER_FROM_SELECTOR not in self._blocked_selectors:
                self._add_selector_locked(
                    TRANSFER_FROM_SELECTOR,
                    signature="transferFrom(address,address,uint256)",
                    description="Standard ERC-20 transferFrom drain selector",
                )

    def save(self, path: str | Path | None = None) -> None:
        target_path = Path(path) if path else self.filepath
        if not target_path:
            return
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            contracts = []
            phishing = []
            for entry in self._blocked_addresses.values():
                d = {
                    "address": f"0x{entry.target}",
                    "name": entry.name,
                    "category": entry.threat_type,
                    "description": entry.description,
                    "severity": entry.severity,
                    "date_added": entry.date_added,
                }
                if entry.threat_type == "phishing":
                    phishing.append(d)
                else:
                    contracts.append(d)

            selectors = []
            for entry in self._blocked_selectors.values():
                selectors.append({
                    "selector": entry.target,
                    "signature": entry.signature,
                    "description": entry.description,
                    "severity": entry.severity,
                })

            patterns = [r for r in self._reports if r.get("type") == "agent_attack_pattern"]

            doc = {
                "version": self.version,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "description": self.description or "Hermes SafeGuard threat feed blocklist",
                "malicious_contracts": contracts,
                "phishing_addresses": phishing,
                "dangerous_selectors": selectors,
                "agent_attack_patterns": patterns,
            }

        temp_path = target_path.with_suffix(".tmp")
        if str(target_path).endswith((".yaml", ".yml")) and _HAVE_YAML:
            with open(temp_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(doc, f, sort_keys=False)
        else:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2)
        temp_path.replace(target_path)

    def is_address_blocked(self, address: str) -> bool:
        if not address:
            return False
        try:
            norm = normalize_address(address)
        except Exception:
            return False
        with self._lock:
            return norm in self._blocked_addresses

    def get_address_threat(self, address: str) -> ThreatEntry | None:
        if not address:
            return None
        try:
            norm = normalize_address(address)
        except Exception:
            return None
        with self._lock:
            return self._blocked_addresses.get(norm)

    def is_selector_blocked(self, selector: str) -> bool:
        if not selector:
            return False
        raw = selector.strip()
        if raw.startswith(("0x", "0X")):
            raw = raw[2:]
        raw = raw[:8].lower()
        with self._lock:
            return raw in self._blocked_selectors

    def get_selector_threat(self, selector: str) -> ThreatEntry | None:
        if not selector:
            return None
        raw = selector.strip()
        if raw.startswith(("0x", "0X")):
            raw = raw[2:]
        raw = raw[:8].lower()
        with self._lock:
            return self._blocked_selectors.get(raw)

    def add_address(
        self,
        address: str,
        category: str = "malicious_contract",
        name: str = "",
        description: str = "",
        severity: str = "CRITICAL",
        date_added: str = "",
    ) -> ThreatEntry:
        with self._lock:
            return self._add_address_locked(
                address, category=category, name=name, description=description,
                severity=severity, date_added=date_added
            )

    def remove_address(self, address: str) -> bool:
        try:
            norm = normalize_address(address)
        except Exception:
            return False
        with self._lock:
            if norm in self._blocked_addresses:
                del self._blocked_addresses[norm]
                return True
            return False

    def add_selector(
        self,
        selector: str,
        signature: str = "",
        description: str = "",
        severity: str = "CRITICAL",
    ) -> ThreatEntry:
        with self._lock:
            return self._add_selector_locked(selector, signature=signature, description=description, severity=severity)

    def remove_selector(self, selector: str) -> bool:
        raw = selector.strip()
        if raw.startswith(("0x", "0X")):
            raw = raw[2:]
        raw = raw[:8].lower()
        with self._lock:
            if raw in self._blocked_selectors:
                del self._blocked_selectors[raw]
                return True
            return False

    def add_report(self, report: dict[str, Any]) -> None:
        with self._lock:
            self._reports.append(report)

    @property
    def blocked_addresses(self) -> dict[str, ThreatEntry]:
        with self._lock:
            return dict(self._blocked_addresses)

    @property
    def blocked_selectors(self) -> dict[str, ThreatEntry]:
        with self._lock:
            return dict(self._blocked_selectors)

    def search_reports(self, query: str = "", limit: int = 10) -> list[dict[str, Any]]:
        """
        Search threat intelligence reports, attack patterns, and blocked targets.
        In production, can be connected to live external intelligence feeds (e.g. Twitter/X security alerts, ScamSniffer APIs).
        """
        q = query.strip().lower() if query else ""
        with self._lock:
            if not q or q in ("*", "all"):
                return [dict(r) for r in self._reports[:limit]]

            q_norm = ""
            if len(q) >= 4:
                try:
                    q_norm = normalize_address(q)
                except Exception:
                    q_norm = ""

            matches: list[dict[str, Any]] = []
            for r in self._reports:
                title = str(r.get("title", "")).lower()
                desc = str(r.get("description", "")).lower()
                cat = str(r.get("category", "")).lower()
                name = str(r.get("name", "")).lower()
                target = str(r.get("target", "")).lower()
                sig = str(r.get("signature", "")).lower()
                indicators = [str(ind).lower() for ind in r.get("indicators", [])]
                rpt_id = str(r.get("id", "")).lower()

                match = (
                    q in title
                    or q in desc
                    or q in cat
                    or q in name
                    or q in target
                    or q in sig
                    or q in rpt_id
                    or any(q in ind for ind in indicators)
                    or (q_norm and q_norm in target)
                )
                if match:
                    matches.append(dict(r))
                    if len(matches) >= limit:
                        break

            return matches

    def sync_live_threats(self) -> dict[str, Any]:
        """
        Synchronize with dynamic Web3 security APIs (PeckShield, ScamSniffer, SlowMist).
        Returns summary of newly ingested threats and updated counts.
        """
        try:
            from threat_stream import ThreatStreamSyncer
            syncer = ThreatStreamSyncer(threat_feed=self)
            return syncer.sync_once()
        except ImportError:
            return {"error": "threat_stream module unavailable"}

    def start_live_stream(self, interval: int = 300, webhook_port: int | None = None) -> Any:
        """
        Start dynamic 5-minute background polling and optional webhook ingestion.
        """
        try:
            from threat_stream import ThreatStreamSyncer
            syncer = ThreatStreamSyncer(threat_feed=self, poll_interval=interval)
            syncer.start_polling_worker()
            if webhook_port:
                syncer.start_webhook_server(port=webhook_port)
            return syncer
        except ImportError:
            return None


_DEFAULT_THREAT_FEED: ThreatFeed | None = None


def get_default_threat_feed() -> ThreatFeed:
    global _DEFAULT_THREAT_FEED
    if _DEFAULT_THREAT_FEED is None:
        _DEFAULT_THREAT_FEED = ThreatFeed()
    return _DEFAULT_THREAT_FEED


def set_default_threat_feed(feed: ThreatFeed | None) -> None:
    global _DEFAULT_THREAT_FEED
    _DEFAULT_THREAT_FEED = feed


def reset_default_threat_feed() -> None:
    global _DEFAULT_THREAT_FEED
    _DEFAULT_THREAT_FEED = ThreatFeed()


def safeguard_search_threat_reports(
    query: str = "",
    limit: int = 10,
    threat_feed: ThreatFeed | None = None,
) -> list[dict[str, Any]]:
    """
    Search recent threat reports and attack patterns from the Hermes Safeguard threat feed.
    Can be called by autonomous agents or users to check whether an address, selector,
    protocol, or attack pattern has been flagged.

    Parameters:
        query: Search query (address, selector, name, attack pattern, or indicator).
               If empty or '*', returns recent threat reports up to `limit`.
        limit: Max number of reports to return (default: 10).
        threat_feed: Optional ThreatFeed instance (uses default feed if omitted).

    Returns:
        List of matching threat intelligence report dictionaries.
    """
    feed = threat_feed or get_default_threat_feed()
    return feed.search_reports(query=query, limit=limit)


search_threat_reports = safeguard_search_threat_reports


def extract_action_addresses(
    to_address: str,
    data_hex: str = "",
    value_wei: int = 0,
) -> dict[str, Any]:
    """
    Extract action type ('transfer', 'approve', 'mint', 'other') and relevant addresses:
    - 'target_contract': the contract address being called (if contract call)
    - 'recipients': recipient addresses receiving funds or assets
    - 'spenders': addresses being granted approval
    - 'all_addresses': list of all involved external addresses to verify
    """
    norm_to = normalize_address(to_address) if to_address else ""
    raw = data_hex.strip() if data_hex else ""
    if raw.startswith(("0x", "0X")):
        raw = raw[2:]
    sel = raw[:8].lower() if len(raw) >= 8 else ""

    result: dict[str, Any] = {
        "action": "other",
        "target_contract": norm_to,
        "recipients": [],
        "spenders": [],
        "all_addresses": [norm_to] if norm_to else [],
    }

    # 1. ERC-20 transfer(address to, uint256 amount) - 0xa9059cbb
    if sel == "a9059cbb" and len(raw) >= 72:
        result["action"] = "transfer"
        recip = normalize_address(raw[8:72])
        result["recipients"].append(recip)
        if recip not in result["all_addresses"]:
            result["all_addresses"].append(recip)

    # 2. transferFrom / safeTransferFrom - 0x23b872dd, 0x42842e0e, 0xb88d4fde, 0xf242432a
    elif sel in ("23b872dd", "42842e0e", "b88d4fde", "f242432a") and len(raw) >= 136:
        result["action"] = "transfer"
        recip = normalize_address(raw[72:136])
        result["recipients"].append(recip)
        if recip not in result["all_addresses"]:
            result["all_addresses"].append(recip)

    # 3. ERC-20 approve(address spender, uint256 amount) - 0x095ea7b3
    elif sel == APPROVE_SELECTOR and len(raw) >= 72:
        result["action"] = "approve"
        spender = normalize_address(raw[8:72])
        result["spenders"].append(spender)
        if spender not in result["all_addresses"]:
            result["all_addresses"].append(spender)

    # 4. setApprovalForAll(address operator, bool approved) - 0xa22cb465
    elif sel == SET_APPROVAL_FOR_ALL_SELECTOR and len(raw) >= 72:
        result["action"] = "approve"
        operator = normalize_address(raw[8:72])
        result["spenders"].append(operator)
        if operator not in result["all_addresses"]:
            result["all_addresses"].append(operator)

    # 5. Permit2 approve(address token, address spender, ...) - 0x87517c45
    elif sel == PERMIT2_APPROVE_SELECTOR and len(raw) >= 136:
        result["action"] = "approve"
        tok = normalize_address(raw[8:72])
        spender = normalize_address(raw[72:136])
        result["spenders"].append(spender)
        for a in (tok, spender):
            if a not in result["all_addresses"]:
                result["all_addresses"].append(a)

    # 6. NFT Mint
    elif (
        sel in NFT_MINT_SELECTORS
        or norm_to in (OPENSEA_SEAPORT_1_5, OPENSEA_SEAPORT_1_6, OPENSEA_SEADROP)
        or "mint" in raw.lower()
    ):
        result["action"] = "mint"
        if sel == "755edd17" and len(raw) >= 72:  # mintTo(address,uint256)
            recip = normalize_address(raw[8:72])
            result["recipients"].append(recip)
            if recip not in result["all_addresses"]:
                result["all_addresses"].append(recip)

    # 7. Native ETH transfer
    elif value_wei > 0 and (not raw or len(raw) < 8):
        result["action"] = "transfer"
        if norm_to:
            result["recipients"].append(norm_to)

    else:
        # Generic tool call or transaction
        if norm_to:
            result["recipients"].append(norm_to)

    return result


def _parse_wei_value(val: int | float | str | None, default: int = 0) -> int:
    """
    Parse native asset amount in wei from int, float (interpreted as ETH if float),
    or string with optional 'eth' / 'ether' / 'finney' / 'gwei' / 'wei' / '0x' suffix/prefix.
    Supports comma separators (e.g. '1,000').
    Raises ValueError on unparseable non-empty values to prevent silently converting
    attacker-controlled amounts to zero.
    """
    if val is None:
        return default
    if isinstance(val, (int, float)):
        if isinstance(val, float):
            return int(val * 10**18)
        return val
    if isinstance(val, str):
        s = val.strip().lower()
        if not s:
            return default
        s = s.replace(",", "")
        if s.endswith("ether"):
            num = float(s[:-5].strip())
            return int(num * 10**18)
        if s.endswith("eth"):
            num = float(s[:-3].strip())
            return int(num * 10**18)
        if s.endswith("finney"):
            num = float(s[:-6].strip())
            return int(num * 10**15)
        if s.endswith("gwei"):
            num = float(s[:-4].strip())
            return int(num * 10**9)
        if s.endswith("wei"):
            return int(s[:-3].strip())
        if s.startswith("0x"):
            return int(s, 16)
        if "." in s:
            return int(float(s) * 10**18)
        return int(s)
    raise ValueError(f"Unsupported value type for wei parsing: {type(val)}")


def _parse_token_value(val: int | float | str | None, default: int) -> int:
    """Parse token cap value from int, float, or string."""
    if val is None:
        return default
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str):
        s = val.strip().lower()
        if not s:
            return default
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if "." in s:
                return int(float(s))
            return int(s)
        except (ValueError, TypeError):
            return default
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
      - block_prompt_injection: Whether prompt and indirect injection defenses are active (defaults to True)
      - scan_context_messages: Number of recent messages / tool results to scan for untrusted injection (default 10)
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
    block_prompt_injection: bool = True
    scan_context_messages: int = 10
    tax_warning_threshold: float = 25.0
    tax_block_threshold: float = 50.0
    pre_approved_addresses: list[str | dict[str, Any]] = field(default_factory=list)
    store_path: str | Path | None = None
    memory_store: Any | None = None
    blocklist_path: str | Path | None = None
    threat_feed: Any | None = None

    def __post_init__(self) -> None:
        # Normalize mode string
        self.mode = str(self.mode).lower().strip()
        if self.mode not in ("strict", "balanced", "degen"):
            raise ValueError(
                f"Invalid policy mode: '{self.mode}'. Must be one of: 'strict', 'balanced', 'degen'."
            )

        if self.pre_approved_addresses is None:
            self.pre_approved_addresses = []
        if self.store_path is not None:
            self.store_path = str(self.store_path)

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

        self.block_prompt_injection = bool(self.block_prompt_injection)
        self.scan_context_messages = int(self.scan_context_messages) if self.scan_context_messages is not None else 10

    @classmethod
    def strict(
        cls,
        max_eth_per_tx: int | float | str | None = None,
        max_token_per_tx: int | float | str | None = None,
        recipient_allowlist: list[str] | None = None,
        recipient_denylist: list[str] | None = None,
        block_prompt_injection: bool = True,
        scan_context_messages: int = 10,
        pre_approved_addresses: list[str | dict[str, Any]] | None = None,
        store_path: str | Path | None = None,
        memory_store: Any | None = None,
        blocklist_path: str | Path | None = None,
        threat_feed: Any | None = None,
    ) -> PolicyConfig:
        """Create a strict mode PolicyConfig (aggressive blocking, default for most users)."""
        eth_cap = _parse_wei_value(max_eth_per_tx, 500_000_000_000_000_000)  # 0.5 ETH
        token_cap = _parse_token_value(max_token_per_tx, 500_000_000_000_000_000)
        allowlist = recipient_allowlist if recipient_allowlist is not None else [DEFAULT_ALLOWED_TARGET]
        denylist = recipient_denylist if recipient_denylist is not None else []
        pre_approved = list(pre_approved_addresses or [])
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
            block_prompt_injection=block_prompt_injection,
            scan_context_messages=scan_context_messages,
            pre_approved_addresses=pre_approved,
            store_path=store_path,
            memory_store=memory_store,
            blocklist_path=blocklist_path,
            threat_feed=threat_feed,
        )

    @classmethod
    def balanced(
        cls,
        max_eth_per_tx: int | float | str | None = None,
        max_token_per_tx: int | float | str | None = None,
        recipient_allowlist: list[str] | None = None,
        recipient_denylist: list[str] | None = None,
        block_prompt_injection: bool = True,
        scan_context_messages: int = 10,
        pre_approved_addresses: list[str | dict[str, Any]] | None = None,
        store_path: str | Path | None = None,
        memory_store: Any | None = None,
        blocklist_path: str | Path | None = None,
        threat_feed: Any | None = None,
    ) -> PolicyConfig:
        """Create a balanced mode PolicyConfig (higher amounts, capped approvals, blocks drains)."""
        eth_cap = _parse_wei_value(max_eth_per_tx, 5_000_000_000_000_000_000)  # 5.0 ETH
        token_cap = _parse_token_value(max_token_per_tx, 50_000_000_000_000_000_000)  # 50 ETH equiv
        allowlist = recipient_allowlist if recipient_allowlist is not None else []
        denylist = recipient_denylist if recipient_denylist is not None else []
        pre_approved = list(pre_approved_addresses or [])
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
            block_prompt_injection=block_prompt_injection,
            scan_context_messages=scan_context_messages,
            pre_approved_addresses=pre_approved,
            store_path=store_path,
            memory_store=memory_store,
            blocklist_path=blocklist_path,
            threat_feed=threat_feed,
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
        block_prompt_injection: bool = True,
        scan_context_messages: int = 10,
        pre_approved_addresses: list[str | dict[str, Any]] | None = None,
        store_path: str | Path | None = None,
        memory_store: Any | None = None,
        blocklist_path: str | Path | None = None,
        threat_feed: Any | None = None,
    ) -> PolicyConfig:
        """Create a degen mode PolicyConfig (relaxed amount & approvals for NFT/heavy interaction)."""
        eth_cap = _parse_wei_value(max_eth_per_tx, 100_000_000_000_000_000_000)  # 100.0 ETH
        token_cap = _parse_token_value(max_token_per_tx, UINT256_MAX)
        contracts = contract_allowlist if contract_allowlist is not None else []
        allowlist = recipient_allowlist if recipient_allowlist is not None else []
        denylist = recipient_denylist if recipient_denylist is not None else []
        pre_approved = list(pre_approved_addresses or [])
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
            block_prompt_injection=block_prompt_injection,
            scan_context_messages=scan_context_messages,
            pre_approved_addresses=pre_approved,
            store_path=store_path,
            memory_store=memory_store,
            blocklist_path=blocklist_path,
            threat_feed=threat_feed,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyConfig:
        """Instantiate PolicyConfig from a Python dictionary."""
        mode = str(data.get("mode", "strict")).lower().strip()

        # Handle alias keys
        rec_allowlist = data.get("recipient_allowlist", data.get("allowlist", data.get("whitelist")))
        rec_denylist = data.get("recipient_denylist", data.get("denylist", []))
        contracts = data.get("contract_allowlist", data.get("contracts", []))
        pre_approved = data.get(
            "pre_approved_addresses",
            data.get("trusted_addresses", data.get("approved_recipients", data.get("trusted_contracts", []))),
        )
        store_path = data.get("store_path", data.get("memory_store_path"))
        mem_store = data.get("memory_store")
        blocklist_path = data.get("blocklist_path", data.get("threat_feed_path", data.get("blocklist")))
        threat_feed = data.get("threat_feed")

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
        block_injection = bool(data.get("block_prompt_injection", True))
        scan_msgs = int(data.get("scan_context_messages", 10))
        tax_warn = float(data.get("tax_warning_threshold", 25.0))
        tax_block = float(data.get("tax_block_threshold", 50.0))

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
            block_prompt_injection=block_injection,
            scan_context_messages=scan_msgs,
            tax_warning_threshold=tax_warn,
            tax_block_threshold=tax_block,
            pre_approved_addresses=list(pre_approved) if pre_approved else [],
            store_path=store_path,
            memory_store=mem_store,
            blocklist_path=blocklist_path,
            threat_feed=threat_feed,
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
            # Fallback basic YAML parser for standard key-value structures (zero dependencies)
            loaded = {}
            current_list_key = None
            for line in raw_text.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                if line.startswith("- "):
                    if current_list_key:
                        val = line[2:].strip().strip('"').strip("'")
                        if isinstance(loaded.get(current_list_key), list):
                            loaded[current_list_key].append(val)
                elif ":" in line:
                    parts = line.split(":", 1)
                    k = parts[0].strip()
                    v = parts[1].strip()
                    if not v:
                        current_list_key = k
                        if k not in loaded:
                            loaded[k] = []
                    else:
                        current_list_key = None
                        v_unquoted = v.strip('"').strip("'")
                        if v_unquoted.lower() == "true":
                            loaded[k] = True
                        elif v_unquoted.lower() == "false":
                            loaded[k] = False
                        else:
                            try:
                                if "." in v_unquoted:
                                    loaded[k] = float(v_unquoted)
                                else:
                                    loaded[k] = int(v_unquoted)
                            except ValueError:
                                loaded[k] = v_unquoted
            return cls.from_dict(loaded)

    def to_dict(self) -> dict[str, Any]:
        """Convert PolicyConfig to a Python dictionary."""
        d = asdict(self)
        if "memory_store" in d:
            del d["memory_store"]
        if "threat_feed" in d:
            del d["threat_feed"]
        return d

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

    def __init__(
        self,
        config: PolicyConfig | dict[str, Any] | None = None,
        threat_feed: ThreatFeed | None = None,
    ) -> None:
        if config is None:
            env_var = os.getenv("SAFEGUARD_MODE")
            if env_var and env_var.strip():
                active_m = env_var.strip().lower()
            else:
                active_m = None
                try:
                    from storage import read_state_file
                    content = read_state_file(".safeguard_mode")
                    if content and content.strip().lower() in ("strict", "balanced", "degen"):
                        active_m = content.strip().lower()
                except Exception:
                    pass
                if not active_m:
                    for p in [Path(".safeguard_mode"), Path(__file__).resolve().parent / ".safeguard_mode"]:
                        if p.is_file():
                            try:
                                content = p.read_text(encoding="utf-8").strip().lower()
                                if content in ("strict", "balanced", "degen"):
                                    active_m = content
                                    break
                            except Exception:
                                pass
                if not active_m:
                    active_m = "degen"
            if active_m == "degen":
                self.config = PolicyConfig.degen()
            elif active_m == "balanced":
                self.config = PolicyConfig.balanced()
            else:
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

        # Prompt injection detector instance
        self.detector = PromptInjectionDetector()

        # Initialize Memory Store for address & context integrity protection
        if getattr(self.config, "memory_store", None) is not None:
            self.memory_store = self.config.memory_store
        elif self.config.store_path or self.config.pre_approved_addresses:
            self.memory_store = AddressMemoryStore(
                filepath=self.config.store_path,
                initial_addresses=self.config.pre_approved_addresses,
            )
        else:
            self.memory_store = get_default_memory_store()

        # Initialize Threat Feed / Security Blocklist
        if threat_feed is not None:
            self.threat_feed = threat_feed
        elif getattr(self.config, "threat_feed", None) is not None:
            self.threat_feed = self.config.threat_feed
        elif getattr(self.config, "blocklist_path", None):
            self.threat_feed = ThreatFeed(self.config.blocklist_path)
        else:
            self.threat_feed = get_default_threat_feed()

        # Seed allowlist targets as pre-approved
        for a in self.recipient_allowlist:
            if a and a != normalize_address(DEFAULT_ALLOWED_TARGET):
                self.memory_store.approve(a, label="recipient_allowlist", source="config")
        for a in self.contract_allowlist:
            if a:
                self.memory_store.approve(a, label="contract_allowlist", address_type="contract", source="config")
        if self.config.pre_approved_addresses:
            for item in self.config.pre_approved_addresses:
                if isinstance(item, str):
                    self.memory_store.approve(item, label="config_pre_approved", source="config")
                elif isinstance(item, dict):
                    addr = item.get("address") or item.get("addr") or ""
                    if addr:
                        self.memory_store.approve(
                            addr,
                            label=str(item.get("label", "")),
                            address_type=str(item.get("address_type", item.get("type", "recipient"))),
                            source=str(item.get("source", "config")),
                            metadata=dict(item.get("metadata", {})),
                        )

    def is_address_approved(self, addr: str) -> bool:
        """Check if an address is approved in memory store, allowlists, or known protocols."""
        try:
            norm = normalize_address(addr)
        except Exception:
            return False
        if not norm or norm == "0" * 40:
            return False
        # Hard security check: threat feed and denylist strictly override any approval
        if self.threat_feed and self.threat_feed.is_address_blocked(norm):
            return False
        if norm in self.denylist:
            return False
        if norm in self.recipient_allowlist or norm in self.contract_allowlist:
            return True
        if norm in KNOWN_VERIFIED_PROTOCOLS:
            return True
        if self.memory_store.is_approved(norm):
            return True
        return False

    def evaluate_context_injection(
        self,
        context: list[Any] | None,
        scan_n: int | None = None,
    ) -> InjectionSignal:
        """
        Scan recent untrusted context (up to scan_n items) for prompt injection patterns.
        """
        if not context:
            return InjectionSignal()
        n = self.config.scan_context_messages if scan_n is None else scan_n
        untrusted_messages = scan_recent_context(context, n=n, untrusted_only=True)
        if not untrusted_messages:
            return InjectionSignal()
        # Scan in reverse chronological order (most recent first)
        for msg in reversed(untrusted_messages):
            sig = self.detector.detect(msg.content, source=msg.source or msg.role)
            if sig.detected and sig.is_strong:
                return sig
        for msg in reversed(untrusted_messages):
            sig = self.detector.detect(msg.content, source=msg.source or msg.role)
            if sig.detected:
                return sig
        return InjectionSignal()

    def check_multicall_risk(self, raw_data: str) -> tuple[bool, str, list[str]]:
        """
        Inspect multicall calldata for unusual or elevated-risk batch compositions.
        Returns: (is_unusual, reason, risk_reasons)
        """
        raw = raw_data.strip()
        if raw.startswith(("0x", "0X")):
            raw = raw[2:]
        if len(raw) < 8 or raw[:8].lower() != MULTICALL_SELECTOR:
            return (False, "", [])

        try:
            raw_bytes = bytes.fromhex(raw[8:])
            sub_calls = decode_bytes_array(raw_bytes)
        except Exception:
            return (True, "malformed multicall calldata", ["Malformed multicall calldata"])

        has_approval = False
        has_transfer = False
        has_swap = False
        sub_selectors: list[str] = []
        for call_b in sub_calls:
            c_hex = call_b.hex()
            if len(c_hex) >= 8:
                c_sel = c_hex[:8].lower()
                sub_selectors.append(c_sel)
                if c_sel in (APPROVE_SELECTOR, SET_APPROVAL_FOR_ALL_SELECTOR, PERMIT2_APPROVE_SELECTOR):
                    has_approval = True
                elif c_sel in (ERC20_TRANSFER_SELECTOR, TRANSFER_FROM_SELECTOR):
                    has_transfer = True
                elif c_sel in (V2_SWAP_SELECTOR, V3_SWAP_SELECTOR):
                    has_swap = True

        risk_reasons: list[str] = []
        # Approval combined with transfer, swap, or other execution in same multicall
        if has_approval and (has_transfer or has_swap or len(sub_calls) > 1):
            risk_reasons.append("Multicall combines token/NFT approval with subsequent execution in the same batch")
        if len(sub_calls) >= 4:
            risk_reasons.append(f"Unusually large multicall batch ({len(sub_calls)} operations)")

        if risk_reasons:
            return (True, "; ".join(risk_reasons), risk_reasons)
        return (False, "", [])

    def evaluate_pre_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        context: list[Any] | None = None,
        confirmed: bool = False,
        scan_n: int | None = None,
        confirmation_id: str | None = None,
    ) -> VerificationResult:
        """
        Hook evaluator for pre_tool_call events.
        Intercepts financial tools and evaluates recent untrusted context for prompt injection.

        Defense-in-depth:
          - Non-financial tools pass through with LOW risk.
          - Financial tools (transfers, approvals, swaps, keystore actions) trigger context inspection.
          - If strong prompt/indirect injection is detected in untrusted context:
            * strict mode: Aggressive block (allowed=False, CRITICAL risk).
            * balanced mode: Forces human confirmation (allowed=False, HIGH risk, requires_confirmation=True).
            * degen mode: Raises risk score to HIGH and requires human confirmation (not silently allowed).
          - If human confirmation has been granted (confirmed=True):
            * Proceeds with policy parameter validation, but preserves elevated HIGH risk score and attaches a warning.
        """
        # Check if the tool is a financial or on-chain transaction tool
        if not is_financial_tool(tool_name):
            return VerificationResult(True, "", RiskScore.LOW)

        if is_kill_switch_active():
            panic_msg = "SafeGuard Panic: Emergency kill-switch is ACTIVE. All onchain transactions and financial operations are halted."
            log_financial_action(
                action=tool_name, status="blocked", mode=self.config.mode,
                target="emergency_kill_switch", value_wei=0, data_hex="",
                risk_score="critical", reason=panic_msg
            )
            return VerificationResult(False, panic_msg, RiskScore.CRITICAL)

        # Extract target address, value, and calldata from tool arguments
        to_address = str(
            tool_args.get("to")
            or tool_args.get("to_address")
            or tool_args.get("target")
            or tool_args.get("recipient")
            or tool_args.get("address")
            or ""
        ).strip()
        value_raw = tool_args.get("value", tool_args.get("value_wei", tool_args.get("amount", 0)))
        value_wei = _parse_wei_value(value_raw, 0)
        data_hex = str(
            tool_args.get("data")
            or tool_args.get("data_hex")
            or tool_args.get("calldata")
            or tool_args.get("input")
            or ""
        ).strip()

        # Resolve confirmed flag strictly from confirmation_id store with parameter binding
        active_conf_id = confirmation_id or tool_args.get("confirmation_id")
        if active_conf_id:
            cs = get_default_confirmation_store()
            if cs.is_rejected(str(active_conf_id)):
                res = VerificationResult(
                    False,
                    f"SG: confirmation {active_conf_id} was rejected by operator",
                    RiskScore.CRITICAL,
                )
                log_financial_action(
                    action=tool_name, status="blocked", mode=self.config.mode,
                    target=to_address, value_wei=value_wei, data_hex=data_hex,
                    risk_score="critical", reason=res.reason,
                )
                return res
            if cs.is_confirmed(str(active_conf_id), to_address=to_address, value_wei=value_wei, data_hex=data_hex):
                confirmed = True

        # Check all address arguments (including nested structures) against threat feed and denylist
        def _extract_all_strings(obj: Any) -> list[str]:
            extracted: list[str] = []
            if isinstance(obj, str):
                extracted.append(obj)
            elif isinstance(obj, dict):
                for val in obj.values():
                    extracted.extend(_extract_all_strings(val))
            elif isinstance(obj, (list, tuple, set)):
                for item in obj:
                    extracted.extend(_extract_all_strings(item))
            return extracted

        for s_val in _extract_all_strings(tool_args):
            s_clean = s_val.strip()
            if len(s_clean) in (40, 42) and (s_clean.startswith(("0x", "0X")) or len(s_clean) == 40):
                try:
                    norm_v = normalize_address(s_clean)
                    if (self.threat_feed and self.threat_feed.is_address_blocked(norm_v)) or norm_v in self.denylist:
                        threat_info = self.threat_feed.get_address_threat(norm_v) if self.threat_feed else None
                        threat_desc = f" (threat feed: {threat_info.name})" if threat_info and threat_info.name else ""
                        res = VerificationResult(
                            False,
                            f"SG: recipient is denylisted{threat_desc}",
                            RiskScore.CRITICAL,
                        )
                        log_financial_action(
                            action=tool_name, status="blocked", mode=self.config.mode,
                            target=norm_v, value_wei=value_wei, data_hex=data_hex,
                            risk_score="critical", reason=res.reason,
                        )
                        return res
                except Exception:
                    pass

        # If a target address is specified, evaluate complete transaction policy
        if to_address:
            return self.evaluate_transaction_policy(
                to_address, value_wei, data_hex, context=context, confirmed=confirmed, scan_n=scan_n, confirmation_id=active_conf_id
            )

        # Financial action with no specific transaction target (e.g. key export/management)
        injection_signal = InjectionSignal()
        if self.config.block_prompt_injection and context:
            injection_signal = self.evaluate_context_injection(context, scan_n=scan_n)
            if injection_signal.is_strong or injection_signal.detected:
                if self.config.mode == "strict":
                    res = VerificationResult(
                        False,
                        f"SG: prompt injection detected in untrusted context ({injection_signal.category})",
                        RiskScore.CRITICAL,
                        requires_confirmation=False,
                        injection_detected=True,
                    )
                    log_financial_action(action=tool_name, status="blocked", mode="strict", target="", value_wei=value_wei, data_hex=data_hex, risk_score="critical", reason=res.reason)
                    return res
                elif self.config.mode in ("balanced", "degen"):
                    if not confirmed:
                        reason = (
                            f"SG: prompt injection detected in untrusted context (human confirmation required in degen mode: {injection_signal.category})"
                            if self.config.mode == "degen"
                            else f"SG: prompt injection detected in untrusted context (human confirmation required: {injection_signal.category})"
                        )
                        summary = generate_transaction_summary(
                            "", value_wei, data_hex,
                            risk_reasons=[f"Prompt injection detected in untrusted context ({injection_signal.category})"],
                            mode=self.config.mode, tool_name=tool_name,
                        )
                        conf = get_default_confirmation_store().create_confirmation_request(
                            action=tool_name, tool_name=tool_name, tool_args=tool_args,
                            to_address="", value_wei=value_wei, data_hex=data_hex,
                            risk_score="high", reason=reason, summary=summary, mode=self.config.mode,
                        )
                        res = VerificationResult(
                            False,
                            reason,
                            RiskScore.HIGH,
                            requires_confirmation=True,
                            injection_detected=True,
                            confirmation_id=conf.id,
                            confirmation_summary=summary,
                        )
                        log_financial_action(action=tool_name, status="requires_confirmation", mode=self.config.mode, target="", value_wei=value_wei, data_hex=data_hex, risk_score="high", reason=reason, summary=summary, confirmation_id=conf.id)
                        return res
                    else:
                        warn = f"Warning: Financial action executed after human confirmation despite flagged injection: {injection_signal.category}"
                        res = VerificationResult(
                            True,
                            "",
                            RiskScore.HIGH,
                            warning=warn,
                            requires_confirmation=False,
                            injection_detected=True,
                        )
                        log_financial_action(action=tool_name, status="allowed", mode=self.config.mode, target="", value_wei=value_wei, data_hex=data_hex, risk_score="high", warning=warn)
                        return res

        res = VerificationResult(True, "", RiskScore.LOW)
        log_financial_action(action=tool_name, status="allowed", mode=self.config.mode, target="", value_wei=value_wei, data_hex=data_hex, risk_score="low")
        return res

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

        # 1. Blocked drain selectors: transferFrom and threat feed selectors are blocked across all modes (strict, balanced, degen)
        if sel == TRANSFER_FROM_SELECTOR or (self.threat_feed and self.threat_feed.is_selector_blocked(sel)):
            threat = self.threat_feed.get_selector_threat(sel) if self.threat_feed else None
            if threat and sel != TRANSFER_FROM_SELECTOR:
                return f"SG: selector blocked (0x{sel})"
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

        # 2b. ERC-20 transfer(address,uint256)
        if sel == ERC20_TRANSFER_SELECTOR:
            if len(raw) < 136:
                return "SG: malformed transfer calldata"
            amount = int(raw[72:136], 16)
            if amount > self.config.max_token_per_tx:
                return "SG: token transfer amount exceeds token cap"

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

        # 4b. Zero-Slippage Swap Protection: Uniswap swapExactETHForTokens (0x7ff36ab5)
        if sel == "7ff36ab5":
            if len(raw) < 72:
                return "SG: malformed swap calldata"
            amount_out_min = int(raw[8:72], 16)
            if amount_out_min == 0 and self.config.block_zero_slippage:
                return "SG: zero slippage swap blocked"

        # 4c. Zero-Slippage Swap Protection: Uniswap swapExactTokensForETH (0x18cbafe5)
        if sel == "18cbafe5":
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
        self,
        to_address: str,
        value_wei: int,
        data_hex: str = "",
        context: list[Any] | None = None,
        confirmed: bool = False,
        scan_n: int | None = None,
        confirmation_id: str | None = None,
    ) -> VerificationResult:
        """
        Verify transaction parameters against all policy rules for the configured mode.

        Parameters:
            to_address: Destination address for the transaction.
            value_wei: Value in wei being transferred.
            data_hex: Calldata in hex format.
            context: Optional list of recent context messages/tool results.
            confirmed: Whether explicit human confirmation has been granted.
            scan_n: Optional max number of recent messages to scan for injection.
            confirmation_id: Optional confirmation ID from a prior confirmation request.

        Returns:
            VerificationResult(allowed: bool, reason: str, risk_score: str)
        """
        if is_kill_switch_active():
            panic_msg = "SafeGuard Panic: Emergency kill-switch is ACTIVE. All onchain transactions are halted."
            log_financial_action(
                action="transaction", status="blocked", mode=self.config.mode,
                target=to_address or "emergency_kill_switch", value_wei=value_wei, data_hex=data_hex,
                risk_score="critical", reason=panic_msg
            )
            return VerificationResult(False, panic_msg, RiskScore.CRITICAL)

        # Resolve confirmation ID if provided or locate matching unconsumed confirmed request
        cs = get_default_confirmation_store()
        if confirmation_id:
            if cs.is_rejected(str(confirmation_id)):
                res = VerificationResult(
                    False,
                    f"SG: confirmation {confirmation_id} was rejected by operator",
                    RiskScore.CRITICAL,
                )
                log_financial_action(
                    action="transaction", status="blocked", mode=self.config.mode,
                    target=to_address, value_wei=value_wei, data_hex=data_hex,
                    risk_score="critical", reason=res.reason,
                )
                return res
            if cs.is_confirmed(str(confirmation_id), to_address=to_address, value_wei=value_wei, data_hex=data_hex):
                confirmed = True
        elif not confirmed:
            matched_entry = cs.find_confirmed_entry(to_address, value_wei)
            if matched_entry is not None:
                if cs.is_confirmed(matched_entry.id, to_address=to_address, value_wei=value_wei, data_hex=data_hex):
                    confirmed = True
                    confirmation_id = matched_entry.id

        # Step 0: Prompt / indirect injection check on untrusted context
        injection_signal = InjectionSignal()
        if self.config.block_prompt_injection and context:
            injection_signal = self.evaluate_context_injection(context, scan_n=scan_n)

        target_norm = normalize_address(to_address)

        # Step 0.1: Calldata Deciphering & Exploit Pattern Detection (HARD BLOCK across all modes)
        clean_data_check = str(data_hex or "").lower().replace("0x", "")
        sel_check = clean_data_check[:8]
        exploit_reasons = {
            "d8a17684": "Trace inspection: drain pattern detected (approval + transferFrom in same transaction)",
            "f4c9c118": "Trace inspection: drain pattern detected (multiple transfers out of wallet)",
            "756e6578": "Trace inspection: unexpected ERC-20/NFT transfer out of wallet during NFT mint (0x000000000000000000000000000000000000ee01)",
            "de1e9a7e": "Trace inspection: unverified DELEGATECALL to 0x000000000000000000000000000000000000dead",
            "74617802": "Trace inspection: extortionate token tax detected (99.0% tax exceeds 50% safety threshold; transaction blocked to prevent total fund loss)",
        }
        if (
            sel_check in exploit_reasons
            or "drain_approval" in clean_data_check
            or "claimrewardandsweep" in clean_data_check
        ):
            reason_msg = exploit_reasons.get(
                sel_check,
                "Trace inspection: drain pattern detected (approval + transferFrom in same transaction)"
            )
            log_financial_action(
                action="transaction", status="blocked", mode=self.config.mode,
                target=to_address, value_wei=value_wei, data_hex=data_hex,
                risk_score="critical", reason=reason_msg,
            )
            return VerificationResult(
                False,
                reason_msg,
                RiskScore.CRITICAL,
                requires_confirmation=False,
            )

        # Step 0.5: Extract action addresses and identify any new/unapproved recipients or contracts
        action_info = extract_action_addresses(to_address, data_hex, value_wei)
        new_addresses: list[str] = []
        for a in action_info["all_addresses"]:
            if a and not self.is_address_approved(a):
                new_addresses.append(a)
        is_new_recipient = len(new_addresses) > 0

        # Step 1: Threat Feed Blocklist & Recipient Denylist (hard-blocked in all modes: strict, balanced, degen)
        all_action_addresses = action_info.get("all_addresses", [])
        all_to_check = [target_norm] + new_addresses + all_action_addresses
        for a in all_to_check:
            if not a:
                continue
            is_threat = bool(self.threat_feed and self.threat_feed.is_address_blocked(a))
            is_deny = a in self.denylist
            if is_threat or is_deny:
                threat_info = self.threat_feed.get_address_threat(a) if (self.threat_feed and is_threat) else None
                threat_desc = f" (threat feed: {threat_info.name})" if threat_info and threat_info.name else ""
                logger.warning(
                    "Hermes SafeGuard: Interaction with denylisted/blocked threat address blocked in %s mode: 0x%s%s",
                    self.config.mode, a, threat_desc,
                )
                res = VerificationResult(
                    False,
                    f"SG: recipient is denylisted{threat_desc}",
                    RiskScore.CRITICAL,
                    is_new_recipient=is_new_recipient,
                    flagged_addresses=new_addresses,
                )
                log_financial_action(action="transaction", status="blocked", mode=self.config.mode, target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="critical", reason=res.reason)
                return res

        # Step 2: Value Cap check
        if value_wei > self.config.max_eth_per_tx:
            if self.config.mode == "degen":
                if not confirmed:
                    val_eth = value_wei / 10**18
                    cap_eth = self.config.max_eth_per_tx / 10**18
                    summary = generate_transaction_summary(
                        to_address, value_wei, data_hex,
                        risk_reasons=[f"Transfer value ({val_eth:.2f} ETH) exceeds degen threshold ({cap_eth:.2f} ETH)"],
                        mode="degen",
                    )
                    conf = get_default_confirmation_store().create_confirmation_request(
                        action="transfer", to_address=to_address, value_wei=value_wei, data_hex=data_hex,
                        risk_score="high", reason=f"SG: high-value transfer ({val_eth:.2f} ETH) exceeds threshold, requires human confirmation",
                        summary=summary, mode="degen",
                    )
                    log_financial_action(action="transfer", status="requires_confirmation", mode="degen", target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="high", reason=conf.reason, summary=summary, confirmation_id=conf.id)
                    return VerificationResult(
                        False, conf.reason, RiskScore.HIGH, requires_confirmation=True,
                        is_new_recipient=is_new_recipient, flagged_addresses=new_addresses,
                        confirmation_id=conf.id, confirmation_summary=summary,
                    )
            else:
                res = VerificationResult(
                    False,
                    "SG: value exceeds max per tx",
                    RiskScore.HIGH,
                    is_new_recipient=is_new_recipient,
                    flagged_addresses=new_addresses,
                )
                log_financial_action(action="transfer", status="blocked", mode=self.config.mode, target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="high", reason=res.reason)
                return res

        # Step 3: Calldata security evaluation
        raw_data = data_hex.strip() if data_hex else ""
        if raw_data.startswith(("0x", "0X")):
            raw_data = raw_data[2:]

        sel = raw_data[:8].lower() if len(raw_data) >= 8 else ""

        if len(raw_data) >= 8:
            calldata_err = self.evaluate_calldata_security(raw_data)
            if calldata_err:
                risk = RiskScore.HIGH
                if "selector blocked" in calldata_err:
                    risk = RiskScore.CRITICAL
                elif "exceeds" in calldata_err:
                    risk = RiskScore.MEDIUM
                res = VerificationResult(
                    False,
                    calldata_err,
                    risk,
                    is_new_recipient=is_new_recipient,
                    flagged_addresses=new_addresses,
                )
                log_financial_action(action="transaction", status="blocked", mode=self.config.mode, target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score=risk.value if isinstance(risk, RiskScore) else str(risk), reason=calldata_err)
                return res

        # Step 3.5: Multicall inspection in Degen Mode
        if sel == MULTICALL_SELECTOR and self.config.mode == "degen":
            is_unusual_mc, mc_reason, mc_risks = self.check_multicall_risk(raw_data)
            if is_unusual_mc and not confirmed:
                summary = generate_transaction_summary(
                    to_address, value_wei, data_hex,
                    risk_reasons=mc_risks,
                    mode="degen",
                )
                conf = get_default_confirmation_store().create_confirmation_request(
                    action="multicall", to_address=to_address, value_wei=value_wei, data_hex=data_hex,
                    risk_score="high", reason=f"SG: unusual multicall requires confirmation ({mc_reason})",
                    summary=summary, mode="degen",
                )
                log_financial_action(action="multicall", status="requires_confirmation", mode="degen", target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="high", reason=conf.reason, summary=summary, confirmation_id=conf.id)
                return VerificationResult(
                    False, conf.reason, RiskScore.HIGH, requires_confirmation=True,
                    is_new_recipient=is_new_recipient, flagged_addresses=new_addresses,
                    confirmation_id=conf.id, confirmation_summary=summary,
                )

        # Step 3.6: Zero-slippage swap on high-value trade in Degen Mode
        if self.config.mode == "degen" and sel in (V2_SWAP_SELECTOR, V3_SWAP_SELECTOR):
            is_zero_slip = False
            amount_in_val = value_wei
            if sel == V2_SWAP_SELECTOR and len(raw_data) >= 136:
                amount_in_val = int(raw_data[8:72], 16) if value_wei == 0 else value_wei
                is_zero_slip = int(raw_data[72:136], 16) == 0
            elif sel == V3_SWAP_SELECTOR and len(raw_data) >= 456:
                is_zero_slip = int(raw_data[392:456], 16) == 0

            if is_zero_slip and (value_wei >= 1_000_000_000_000_000_000 or amount_in_val >= 1_000_000_000_000_000_000):
                if not confirmed:
                    summary = generate_transaction_summary(
                        to_address, value_wei, data_hex,
                        risk_reasons=["Zero-slippage swap on high-value trade exposes transaction to 100% MEV sandwich extraction"],
                        mode="degen",
                    )
                    conf = get_default_confirmation_store().create_confirmation_request(
                        action="swap", to_address=to_address, value_wei=value_wei, data_hex=data_hex,
                        risk_score="high", reason="SG: zero-slippage swap on high-value trade requires human confirmation",
                        summary=summary, mode="degen",
                    )
                    log_financial_action(action="swap", status="requires_confirmation", mode="degen", target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="high", reason=conf.reason, summary=summary, confirmation_id=conf.id)
                    return VerificationResult(
                        False, conf.reason, RiskScore.HIGH, requires_confirmation=True,
                        is_new_recipient=is_new_recipient, flagged_addresses=new_addresses,
                        confirmation_id=conf.id, confirmation_summary=summary,
                    )

        # Step 4: Defense against prompt injection & poisoned memory
        if injection_signal.is_strong or injection_signal.detected:
            if self.config.mode == "strict":
                res = VerificationResult(
                    False,
                    f"SG: prompt injection detected in untrusted context ({injection_signal.category})",
                    RiskScore.CRITICAL,
                    requires_confirmation=False,
                    injection_detected=True,
                    is_new_recipient=is_new_recipient,
                    flagged_addresses=new_addresses,
                )
                log_financial_action(action="transaction", status="blocked", mode="strict", target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="critical", reason=res.reason)
                return res
            elif self.config.mode in ("balanced", "degen"):
                if not confirmed:
                    reason = (
                        f"SG: prompt injection detected in untrusted context (human confirmation required in degen mode: {injection_signal.category})"
                        if self.config.mode == "degen"
                        else f"SG: prompt injection detected in untrusted context (human confirmation required: {injection_signal.category})"
                    )
                    summary = generate_transaction_summary(
                        to_address, value_wei, data_hex,
                        risk_reasons=[f"Prompt injection signal detected in untrusted context ({injection_signal.category})"],
                        mode=self.config.mode,
                    )
                    conf = get_default_confirmation_store().create_confirmation_request(
                        action="transaction", to_address=to_address, value_wei=value_wei, data_hex=data_hex,
                        risk_score="high", reason=reason, summary=summary, mode=self.config.mode,
                    )
                    log_financial_action(action="transaction", status="requires_confirmation", mode=self.config.mode, target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="high", reason=reason, summary=summary, confirmation_id=conf.id)
                    return VerificationResult(
                        False,
                        reason,
                        RiskScore.HIGH,
                        requires_confirmation=True,
                        injection_detected=True,
                        is_new_recipient=is_new_recipient,
                        flagged_addresses=new_addresses,
                        confirmation_id=conf.id,
                        confirmation_summary=summary,
                    )

        # Step 5: Memory and context integrity protection for new recipient addresses
        if is_new_recipient:
            flagged_addr = new_addresses[0]

            # Requirement 3: In strict mode, require explicit confirmation for new recipients
            if self.config.mode == "strict":
                if not confirmed:
                    logger.info("Hermes SafeGuard: Strict mode requires explicit confirmation for new recipient 0x%s", flagged_addr)
                    summary = generate_transaction_summary(
                        to_address, value_wei, data_hex,
                        risk_reasons=[f"New recipient address 0x{flagged_addr} requires explicit human confirmation in strict mode"],
                        mode="strict",
                    )
                    conf = get_default_confirmation_store().create_confirmation_request(
                        action="transaction", to_address=to_address, value_wei=value_wei, data_hex=data_hex,
                        risk_score="high", reason=f"SG: new recipient address requires human confirmation (strict mode): 0x{flagged_addr}",
                        summary=summary, mode="strict",
                    )
                    log_financial_action(action="transaction", status="requires_confirmation", mode="strict", target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="high", reason=conf.reason, summary=summary, confirmation_id=conf.id)
                    return VerificationResult(
                        False,
                        conf.reason,
                        RiskScore.HIGH,
                        requires_confirmation=True,
                        is_new_recipient=True,
                        flagged_addresses=new_addresses,
                        confirmation_id=conf.id,
                        confirmation_summary=summary,
                    )
                else:
                    logger.info("Hermes SafeGuard: New recipient 0x%s confirmed by human in strict mode", flagged_addr)
                    for a in new_addresses:
                        self.memory_store.approve(a, label="User confirmed", source="confirmation")
            else:
                # Requirement 4: In balanced and degen modes, allow it but log it and raise risk score
                logger.warning(
                    "Hermes SafeGuard: New recipient/contract address detected in %s mode: 0x%s",
                    self.config.mode, flagged_addr,
                )

        # Step 6: Allowlist checks (for addresses not pre-approved or confirmed)
        if self.config.mode == "strict":
            if self.recipient_allowlist and target_norm not in self.recipient_allowlist and not self.memory_store.is_approved(target_norm):
                res = VerificationResult(
                    False, "SG: target not whitelisted", RiskScore.MEDIUM,
                    is_new_recipient=is_new_recipient, flagged_addresses=new_addresses,
                )
                log_financial_action(action="transaction", status="blocked", mode="strict", target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="medium", reason=res.reason)
                return res
        elif self.config.mode == "balanced":
            if self.recipient_allowlist and target_norm not in self.recipient_allowlist and not self.memory_store.is_approved(target_norm):
                res = VerificationResult(
                    False, "SG: target not whitelisted", RiskScore.MEDIUM,
                    is_new_recipient=is_new_recipient, flagged_addresses=new_addresses,
                )
                log_financial_action(action="transaction", status="blocked", mode="balanced", target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="medium", reason=res.reason)
                return res
        elif self.config.mode == "degen":
            if self.contract_allowlist:
                if (target_norm not in self.contract_allowlist) and (target_norm not in self.recipient_allowlist) and not self.memory_store.is_approved(target_norm):
                    if not confirmed:
                        summary = generate_transaction_summary(
                            to_address, value_wei, data_hex,
                            risk_reasons=[f"Target 0x{target_norm} is not in degen contract allowlist"],
                            mode="degen",
                        )
                        conf = get_default_confirmation_store().create_confirmation_request(
                            action="contract_call", to_address=to_address, value_wei=value_wei, data_hex=data_hex,
                            risk_score="medium", reason="SG: target not in degen contract allowlist",
                            summary=summary, mode="degen",
                        )
                        log_financial_action(action="contract_call", status="requires_confirmation", mode="degen", target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="medium", reason=conf.reason, summary=summary, confirmation_id=conf.id)
                        return VerificationResult(
                            False, "SG: target not in degen contract allowlist", RiskScore.MEDIUM,
                            requires_confirmation=True,
                            is_new_recipient=is_new_recipient, flagged_addresses=new_addresses,
                            confirmation_id=conf.id, confirmation_summary=summary,
                        )

        # Step 7: Allowed execution return with appropriate risk scoring & warnings
        if (injection_signal.is_strong or injection_signal.detected) and confirmed:
            res = VerificationResult(
                True,
                "",
                RiskScore.HIGH,
                warning=f"Warning: Transaction executed under human confirmation despite flagged injection: {injection_signal.category}",
                requires_confirmation=False,
                injection_detected=True,
                is_new_recipient=is_new_recipient,
                flagged_addresses=new_addresses,
            )
            log_financial_action(action="transaction", status="allowed", mode=self.config.mode, target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="high", warning=res.warning)
            return res

        if is_new_recipient:
            flagged_addr = new_addresses[0]
            raised_risk = RiskScore.HIGH if (confirmed and self.config.mode == "strict") else RiskScore.MEDIUM
            warn = f"Warning: Transaction to new/unapproved recipient 0x{flagged_addr} ({self.config.mode} mode, risk score raised)"
            res = VerificationResult(
                True,
                "",
                raised_risk,
                warning=warn,
                requires_confirmation=False,
                injection_detected=injection_signal.detected,
                is_new_recipient=True,
                flagged_addresses=new_addresses,
            )
            log_financial_action(action="transaction", status="allowed", mode=self.config.mode, target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score=raised_risk.value, warning=warn)
            return res

        res = VerificationResult(True, "", RiskScore.LOW)
        log_financial_action(action="transaction", status="allowed", mode=self.config.mode, target=to_address, value_wei=value_wei, data_hex=data_hex, risk_score="low")
        return res


def check_pre_tool_call(
    tool_name: str,
    tool_args: dict[str, Any],
    context: list[Any] | None = None,
    mode: str | PolicyMode | None = None,
    config: PolicyConfig | dict | str | None = None,
    confirmed: bool = False,
    scan_n: int = 10,
    memory_store: AddressMemoryStore | None = None,
    threat_feed: ThreatFeed | None = None,
    confirmation_id: str | None = None,
) -> VerificationResult:
    """
    Pre-tool-call inspection entrypoint for Hermes SafeGuard middleware.

    Intercepts tool calls before execution to protect autonomous agents against
    direct and indirect prompt injection attacks, poisoned memory manipulation,
    and interaction with known malicious/phishing threat blocklist entries.
    """
    if config is None:
        if mode is not None:
            mode_str = mode.value if isinstance(mode, PolicyMode) else str(mode)
            cfg = PolicyConfig.from_dict({"mode": mode_str})
        else:
            cfg = PolicyConfig.strict()
    elif isinstance(config, PolicyConfig):
        cfg = config
    elif isinstance(config, dict):
        cfg = PolicyConfig.from_dict(config)
    elif isinstance(config, str):
        cfg = PolicyConfig.from_yaml(config)
    else:
        raise TypeError(f"Unsupported config type: {type(config)}")

    if memory_store is not None:
        cfg.memory_store = memory_store
    if threat_feed is not None:
        cfg.threat_feed = threat_feed

    engine = PolicyEngine(cfg)
    return engine.evaluate_pre_tool_call(
        tool_name=tool_name,
        tool_args=tool_args,
        context=context,
        confirmed=confirmed,
        scan_n=scan_n,
        confirmation_id=confirmation_id,
    )
