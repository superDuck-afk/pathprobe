"""Shared data classes used across all PathProbe modules.

Every public type is a frozen or mutable dataclass.  Payload metadata is
intentionally lightweight (no slots, no __post_init__ validation) because
the payload engine creates thousands of instances per scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────
#  Payload types
# ─────────────────────────────────────────────

@dataclass
class PayloadMeta:
    """Metadata carried alongside every payload string.

    The adaptive fuzzing engine reads these fields to decide which
    *axis* to expand when a payload hits (e.g. try more encodings if
    the encoding field was non-'none' on a successful probe).
    """
    encoding: str = "none"
    depth: int = 0
    target_file: str = ""
    technique: str = "standard"
    phase: str = "discovery"         # discovery | exploitation
    separator: str = "/"
    suffix: str = ""
    traversal_variant: str = "standard"
    category: str = "generated"
    waf_transform: str = "none"


# ─────────────────────────────────────────────
#  HTTP types
# ─────────────────────────────────────────────

@dataclass
class Response:
    """Normalised HTTP response returned by the transport layer."""
    status: int
    headers: Dict[str, str]
    body: str
    length: int
    elapsed: float
    url: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Response":
        return cls(
            status=d.get("status", 0),
            headers=d.get("headers", {}),
            body=d.get("body", ""),
            length=d.get("length", 0),
            elapsed=d.get("elapsed", 0.0),
            url=d.get("url", ""),
        )


# ─────────────────────────────────────────────
#  Analysis types
# ─────────────────────────────────────────────

@dataclass
class SignatureMatch:
    """One matching content/error signature."""
    signature: str
    description: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    os: str                # Linux | Windows | Any


@dataclass
class AnalysisResult:
    """Output of the response analyzer — pure data, no side effects."""
    vulnerable: bool = False
    confidence: str = "NONE"         # HIGH | MEDIUM | LOW | NONE
    confidence_score: int = 0        # 0-100 composite score
    matches: List[SignatureMatch] = field(default_factory=list)
    similarity_score: float = 1.0
    error_detected: bool = False
    error_signatures_hit: List[str] = field(default_factory=list)
    content_type_changed: bool = False
    baseline_ct: str = ""
    response_ct: str = ""
    size_anomaly: bool = False
    status: int = 0
    length: int = 0
    disclosed_paths: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────
#  Finding / result types
# ─────────────────────────────────────────────

@dataclass
class Finding:
    """A single vulnerability finding, possibly verified."""
    param: str
    payload: str
    payload_meta: PayloadMeta
    url: str
    status: int
    response_length: int
    elapsed: float
    confidence: str
    confidence_score: int
    signatures: List[SignatureMatch]
    size_anomaly: bool
    similarity_score: float
    error_detected: bool
    error_signatures_hit: List[str]
    content_type_changed: bool
    evidence_snippet: str
    post_mode: str = "GET"
    waf_technique: str = "none"
    timestamp: str = ""
    verified: bool = False
    verification_count: int = 0
    consistent: bool = False
    disclosed_paths: List[str] = field(default_factory=list)
    curl_poc: str = ""
    python_poc: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    @property
    def severity(self) -> str:
        """Highest severity among matched signatures, or LOW."""
        if not self.signatures:
            return "LOW"
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return min(self.signatures, key=lambda s: order.get(s.severity, 99)).severity

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to plain dict for JSON reporting."""
        return {
            "param": self.param,
            "payload": self.payload,
            "payload_meta": {
                "encoding": self.payload_meta.encoding,
                "depth": self.payload_meta.depth,
                "target_file": self.payload_meta.target_file,
                "technique": self.payload_meta.technique,
                "phase": self.payload_meta.phase,
                "waf_transform": self.payload_meta.waf_transform,
            },
            "url": self.url,
            "status": self.status,
            "response_length": self.response_length,
            "elapsed": self.elapsed,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "severity": self.severity,
            "signatures": [
                {"signature": s.signature, "description": s.description,
                 "severity": s.severity, "os": s.os}
                for s in self.signatures
            ],
            "size_anomaly": self.size_anomaly,
            "similarity_score": self.similarity_score,
            "error_detected": self.error_detected,
            "error_signatures_hit": self.error_signatures_hit,
            "content_type_changed": self.content_type_changed,
            "evidence_snippet": self.evidence_snippet,
            "post_mode": self.post_mode,
            "waf_technique": self.waf_technique,
            "timestamp": self.timestamp,
            "verified": self.verified,
            "disclosed_paths": self.disclosed_paths,
            "curl_poc": self.curl_poc,
        }


# ─────────────────────────────────────────────
#  Recon / parameter types
# ─────────────────────────────────────────────

@dataclass
class ParamScore:
    """Scoring result for a single parameter."""
    name: str
    value: str = ""
    score: int = 0
    priority: str = "LOW"            # HIGH | MEDIUM | LOW | SKIP
    signals: List[str] = field(default_factory=list)


@dataclass
class ScanTarget:
    """One endpoint + parameter combination to be scanned."""
    url: str
    param: str
    method: str = "GET"              # GET | POST
    priority: str = "HIGH"
    score: int = 0
    post_mode: Optional[str] = None  # form | json | xml | multipart | ...
    param_value: str = ""            # original value (for value-based analysis)


@dataclass
class TargetInfo:
    """Fingerprint of the remote target."""
    os: Optional[str] = None         # linux | windows
    server: Optional[str] = None     # apache | nginx | iis | tomcat
    framework: Optional[str] = None  # laravel | django | spring | express ...
    language: Optional[str] = None   # php | java | dotnet | python | nodejs
    extra_payloads: List[Tuple[str, Dict[str, str]]] = field(default_factory=list)
