"""Findings: what changed, how severe it is and why it matters."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {names})") from None


SEVERITY_LABELS = tuple(s.label for s in Severity)


def fingerprint(*parts: str) -> str:
    """Stable identity of a finding across runs, used for dedupe and alert state."""
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Finding:
    """One detected change. Detectors fill everything except severity, why and rule_id."""

    detector: str
    change_type: str
    subject: str
    title: str
    target: str = ""
    profile: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    """Facts that rules can match on (booleans, numbers, short strings)."""
    evidence: dict[str, Any] = field(default_factory=dict)
    """Before/after values and blob digests (``*_blob`` keys) supporting the finding."""
    severity: Severity = Severity.INFO
    why: str = ""
    rule_id: str = ""

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.target, self.profile, self.detector, self.change_type, self.subject)

    @property
    def id(self) -> str:
        return self.fingerprint[:16]

    def graded(self, severity: Severity, why: str, rule_id: str) -> Finding:
        return replace(self, severity=severity, why=why, rule_id=rule_id)

    def scoped(self, target: str, profile: str) -> Finding:
        return replace(self, target=target, profile=profile)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "target": self.target,
            "profile": self.profile,
            "detector": self.detector,
            "change_type": self.change_type,
            "severity": self.severity.label,
            "title": self.title,
            "why": self.why,
            "rule_id": self.rule_id,
            "subject": self.subject,
            "attributes": self.attributes,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            detector=data["detector"],
            change_type=data["change_type"],
            subject=data["subject"],
            title=data["title"],
            target=data.get("target", ""),
            profile=data.get("profile", ""),
            attributes=dict(data.get("attributes", {})),
            evidence=dict(data.get("evidence", {})),
            severity=Severity.parse(data.get("severity", "info")),
            why=data.get("why", ""),
            rule_id=data.get("rule_id", ""),
        )
