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
    ):
        return False
    if name in FINANCIAL_TOOLS:
        return True
    financial_keywords = ("transfer", "swap", "approve", "send_tx", "sendtransaction", "wallet", "payout")
    return any(kw in name for kw in financial_keywords)


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
      2. Instruction overrides & jailbreaks ("ignore previous instructions", "disregard prior directives", etc.).
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
        r"(?:send|transfer)\s+(?:eth|funds|tokens|balance)\s+to\s+(?:0x[0-9a-fA-F]{40}|attacker|me|destination)",
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
    .injection_detected, .is_new_recipient, .flagged_addresses).
    """
    allowed: bool
    reason: str
    risk_score: str
    warning: str
    requires_confirmation: bool
    injection_detected: bool
    is_new_recipient: bool
    flagged_addresses: list[str]

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


# Well-known protocol & marketplace addresses
OPENSEA_SEAPORT_1_5 = normalize_address("0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC")
OPENSEA_SEAPORT_1_6 = normalize_address("0x0000000000000068F116a894984e2DB1123eB395")
OPENSEA_SEADROP = normalize_address("0x00005EA00Ac477B1030CE78506496e8C2dE24bf5")
UNISWAP_V2_ROUTER = normalize_address("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")
UNISWAP_V3_ROUTER = normalize_address("0xE592427A0AEce92De3Edee1F18E0157C05861564")
UNISWAP_UNIVERSAL_ROUTER = normalize_address("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD")

KNOWN_VERIFIED_PROTOCOLS: set[str] = {
    OPENSEA_SEAPORT_1_5,
    OPENSEA_SEAPORT_1_6,
    OPENSEA_SEADROP,
    UNISWAP_V2_ROUTER,
    UNISWAP_V3_ROUTER,
    UNISWAP_UNIVERSAL_ROUTER,
    normalize_address(DEFAULT_ALLOWED_TARGET),
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
        return {
            "address": self.address,
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

    @property
    def approved_addresses(self) -> set[str]:
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
        norm = normalize_address(address)
        with self._lock:
            return self._entries.get(norm)

    def remove(self, address: str) -> bool:
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


_DEFAULT_MEMORY_STORE: AddressMemoryStore | None = None


def get_default_memory_store() -> AddressMemoryStore:
    global _DEFAULT_MEMORY_STORE
    if _DEFAULT_MEMORY_STORE is None:
        _DEFAULT_MEMORY_STORE = AddressMemoryStore()
    return _DEFAULT_MEMORY_STORE


def set_default_memory_store(store: AddressMemoryStore | None) -> None:
    global _DEFAULT_MEMORY_STORE
    _DEFAULT_MEMORY_STORE = store


def reset_default_memory_store() -> None:
    global _DEFAULT_MEMORY_STORE
    _DEFAULT_MEMORY_STORE = AddressMemoryStore()


def safeguard_approve_address(
    address: str,
    label: str = "",
    address_type: str = "recipient",
    store: AddressMemoryStore | None = None,
) -> dict[str, Any]:
    """
    User tool/helper to pre-approve common addresses (e.g. secondary wallet, known NFT contracts).
    """
    norm = normalize_address(address)
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
    pre_approved_addresses: list[str | dict[str, Any]] = field(default_factory=list)
    store_path: str | Path | None = None
    memory_store: Any | None = None

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
            pre_approved_addresses=list(pre_approved) if pre_approved else [],
            store_path=store_path,
            memory_store=mem_store,
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
        d = asdict(self)
        if "memory_store" in d:
            del d["memory_store"]
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
        norm = normalize_address(addr)
        if not norm or norm == "0" * 40:
            return True
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

    def evaluate_pre_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        context: list[Any] | None = None,
        confirmed: bool = False,
        scan_n: int | None = None,
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

        # Extract target address, value, and calldata from tool arguments
        to_address = str(
            tool_args.get("to")
            or tool_args.get("to_address")
            or tool_args.get("target")
            or tool_args.get("recipient")
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

        # If a target address is specified, evaluate complete transaction policy
        if to_address:
            return self.evaluate_transaction_policy(
                to_address, value_wei, data_hex, context=context, confirmed=confirmed, scan_n=scan_n
            )

        # Financial action with no specific transaction target (e.g. key export/management)
        injection_signal = InjectionSignal()
        if self.config.block_prompt_injection and context:
            injection_signal = self.evaluate_context_injection(context, scan_n=scan_n)
            if injection_signal.is_strong or injection_signal.detected:
                if self.config.mode == "strict":
                    return VerificationResult(
                        False,
                        f"SG: prompt injection detected in untrusted context ({injection_signal.category})",
                        RiskScore.CRITICAL,
                        requires_confirmation=False,
                        injection_detected=True,
                    )
                elif self.config.mode in ("balanced", "degen"):
                    if not confirmed:
                        reason = (
                            f"SG: prompt injection detected in untrusted context (human confirmation required in degen mode: {injection_signal.category})"
                            if self.config.mode == "degen"
                            else f"SG: prompt injection detected in untrusted context (human confirmation required: {injection_signal.category})"
                        )
                        return VerificationResult(
                            False,
                            reason,
                            RiskScore.HIGH,
                            requires_confirmation=True,
                            injection_detected=True,
                        )
                    else:
                        return VerificationResult(
                            True,
                            "",
                            RiskScore.HIGH,
                            warning=f"Warning: Financial action executed after human confirmation despite flagged injection: {injection_signal.category}",
                            requires_confirmation=False,
                            injection_detected=True,
                        )

        return VerificationResult(True, "", RiskScore.LOW)

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
        self,
        to_address: str,
        value_wei: int,
        data_hex: str = "",
        context: list[Any] | None = None,
        confirmed: bool = False,
        scan_n: int | None = None,
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

        Returns:
            VerificationResult(allowed: bool, reason: str, risk_score: str)
        """
        # Step 0: Prompt / indirect injection check on untrusted context
        injection_signal = InjectionSignal()
        if self.config.block_prompt_injection and context:
            injection_signal = self.evaluate_context_injection(context, scan_n=scan_n)

        target_norm = normalize_address(to_address)

        # Step 0.5: Extract action addresses and identify any new/unapproved recipients or contracts
        action_info = extract_action_addresses(to_address, data_hex, value_wei)
        new_addresses: list[str] = []
        for a in action_info["all_addresses"]:
            if a and not self.is_address_approved(a):
                new_addresses.append(a)
        is_new_recipient = len(new_addresses) > 0

        # Step 1: Recipient Denylist (enforced in all modes: strict, balanced, degen)
        if target_norm in self.denylist or any(a in self.denylist for a in new_addresses):
            return VerificationResult(
                False,
                "SG: recipient is denylisted",
                RiskScore.CRITICAL,
                is_new_recipient=is_new_recipient,
                flagged_addresses=new_addresses,
            )

        # Step 2: Value Cap check
        if value_wei > self.config.max_eth_per_tx:
            return VerificationResult(
                False,
                "SG: value exceeds max per tx",
                RiskScore.HIGH,
                is_new_recipient=is_new_recipient,
                flagged_addresses=new_addresses,
            )

        # Step 3: Calldata security evaluation
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
                return VerificationResult(
                    False,
                    calldata_err,
                    risk,
                    is_new_recipient=is_new_recipient,
                    flagged_addresses=new_addresses,
                )

        # Step 4: Defense against prompt injection & poisoned memory
        if injection_signal.is_strong or injection_signal.detected:
            if self.config.mode == "strict":
                return VerificationResult(
                    False,
                    f"SG: prompt injection detected in untrusted context ({injection_signal.category})",
                    RiskScore.CRITICAL,
                    requires_confirmation=False,
                    injection_detected=True,
                    is_new_recipient=is_new_recipient,
                    flagged_addresses=new_addresses,
                )
            elif self.config.mode == "balanced":
                if not confirmed:
                    return VerificationResult(
                        False,
                        f"SG: prompt injection detected in untrusted context (human confirmation required: {injection_signal.category})",
                        RiskScore.HIGH,
                        requires_confirmation=True,
                        injection_detected=True,
                        is_new_recipient=is_new_recipient,
                        flagged_addresses=new_addresses,
                    )
            elif self.config.mode == "degen":
                if not confirmed:
                    return VerificationResult(
                        False,
                        f"SG: prompt injection detected in untrusted context (human confirmation required in degen mode: {injection_signal.category})",
                        RiskScore.HIGH,
                        requires_confirmation=True,
                        injection_detected=True,
                        is_new_recipient=is_new_recipient,
                        flagged_addresses=new_addresses,
                    )

        # Step 5: Memory and context integrity protection for new recipient addresses
        if is_new_recipient:
            flagged_addr = new_addresses[0]

            # Requirement 3: In strict mode, require explicit confirmation for new recipients
            if self.config.mode == "strict":
                if not confirmed:
                    logger.info("Hermes SafeGuard: Strict mode requires explicit confirmation for new recipient 0x%s", flagged_addr)
                    return VerificationResult(
                        False,
                        f"SG: new recipient address requires human confirmation (strict mode): 0x{flagged_addr}",
                        RiskScore.HIGH,
                        requires_confirmation=True,
                        is_new_recipient=True,
                        flagged_addresses=new_addresses,
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
                return VerificationResult(
                    False, "SG: target not whitelisted", RiskScore.MEDIUM,
                    is_new_recipient=is_new_recipient, flagged_addresses=new_addresses,
                )
        elif self.config.mode == "balanced":
            if self.recipient_allowlist and target_norm not in self.recipient_allowlist and not self.memory_store.is_approved(target_norm):
                return VerificationResult(
                    False, "SG: target not whitelisted", RiskScore.MEDIUM,
                    is_new_recipient=is_new_recipient, flagged_addresses=new_addresses,
                )
        elif self.config.mode == "degen":
            if self.contract_allowlist:
                if (target_norm not in self.contract_allowlist) and (target_norm not in self.recipient_allowlist) and not self.memory_store.is_approved(target_norm):
                    return VerificationResult(
                        False, "SG: target not in degen contract allowlist", RiskScore.MEDIUM,
                        is_new_recipient=is_new_recipient, flagged_addresses=new_addresses,
                    )
            elif self.recipient_allowlist:
                if target_norm not in self.recipient_allowlist and not self.memory_store.is_approved(target_norm):
                    return VerificationResult(
                        False, "SG: target not whitelisted", RiskScore.MEDIUM,
                        is_new_recipient=is_new_recipient, flagged_addresses=new_addresses,
                    )

        # Step 7: Allowed execution return with appropriate risk scoring & warnings
        if (injection_signal.is_strong or injection_signal.detected) and confirmed:
            return VerificationResult(
                True,
                "",
                RiskScore.HIGH,
                warning=f"Warning: Transaction executed under human confirmation despite flagged injection: {injection_signal.category}",
                requires_confirmation=False,
                injection_detected=True,
                is_new_recipient=is_new_recipient,
                flagged_addresses=new_addresses,
            )

        if is_new_recipient:
            flagged_addr = new_addresses[0]
            raised_risk = RiskScore.HIGH if (confirmed and self.config.mode == "strict") else RiskScore.MEDIUM
            warn = f"Warning: Transaction to new/unapproved recipient 0x{flagged_addr} ({self.config.mode} mode, risk score raised)"
            return VerificationResult(
                True,
                "",
                raised_risk,
                warning=warn,
                requires_confirmation=False,
                injection_detected=injection_signal.detected,
                is_new_recipient=True,
                flagged_addresses=new_addresses,
            )

        return VerificationResult(True, "", RiskScore.LOW)


def check_pre_tool_call(
    tool_name: str,
    tool_args: dict[str, Any],
    context: list[Any] | None = None,
    mode: str | PolicyMode | None = None,
    config: PolicyConfig | dict | str | None = None,
    confirmed: bool = False,
    scan_n: int = 10,
    memory_store: AddressMemoryStore | None = None,
) -> VerificationResult:
    """
    Pre-tool-call inspection entrypoint for Hermes SafeGuard middleware.

    Intercepts tool calls before execution to protect autonomous agents against
    direct and indirect prompt injection attacks and poisoned memory manipulation.
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

    engine = PolicyEngine(cfg)
    return engine.evaluate_pre_tool_call(
        tool_name=tool_name,
        tool_args=tool_args,
        context=context,
        confirmed=confirmed,
        scan_n=scan_n,
    )
