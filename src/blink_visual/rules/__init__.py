"""Declarative severity rules: ``(detector, change_type, conditions) -> severity + why``.

Rules are evaluated in order and the first match wins. Project rules (``rules:`` in
``blink.yaml``) are evaluated before the packaged defaults, so they can override them.

Conditions in ``when`` match finding attributes::

    when:
      cross_origin: true              # equality
      changed_percentage: {gte: 2}    # gt, gte, lt, lte
      header: {in: [x-frame-options, content-security-policy]}
      card_like: {exists: true}
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..errors import ConfigError
from ..findings import SEVERITY_LABELS, Finding, Severity

OPERATORS = frozenset({"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "exists"})
UNMATCHED_RULE = "unmatched"


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    detector: str
    change_type: str = "*"
    when: dict[str, Any] = Field(default_factory=dict)
    severity: Literal["info", "low", "medium", "high", "critical"]
    why: str = Field(min_length=1)

    @field_validator("when")
    @classmethod
    def _operators(cls, value: dict[str, Any]) -> dict[str, Any]:
        for key, condition in value.items():
            if isinstance(condition, dict):
                unknown = set(condition) - OPERATORS
                if unknown or not condition:
                    raise ValueError(
                        f"condition on '{key}' uses unknown operator(s) {sorted(unknown)}; "
                        f"allowed: {sorted(OPERATORS)}"
                    )
        return value

    def matches(self, finding: Finding) -> bool:
        if self.detector not in ("*", finding.detector):
            return False
        if self.change_type not in ("*", finding.change_type):
            return False
        return all(_check(finding.attributes, k, c) for k, c in self.when.items())


class RuleSet(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    rules: list[Rule] = Field(default_factory=list)


def _compare(op: str, actual: Any, expected: Any) -> bool:
    try:
        if op == "eq":
            return bool(actual == expected)
        if op == "ne":
            return bool(actual != expected)
        if op == "gt":
            return bool(actual > expected)
        if op == "gte":
            return bool(actual >= expected)
        if op == "lt":
            return bool(actual < expected)
        if op == "lte":
            return bool(actual <= expected)
        if op == "in":
            return actual in expected
        if op == "not_in":
            return actual not in expected
    except TypeError:
        return False
    raise AssertionError(op)  # pragma: no cover - guarded by the validator


def _check(attributes: dict[str, Any], key: str, condition: Any) -> bool:
    present = key in attributes
    actual = attributes.get(key)
    if not isinstance(condition, dict):
        return present and actual == condition
    for op, expected in condition.items():
        if op == "exists":
            if present != bool(expected):
                return False
        elif not present or not _compare(op, actual, expected):
            return False
    return True


def parse_rules(data: Any, *, source: str) -> RuleSet:
    try:
        return RuleSet.model_validate(data if data is not None else {})
    except ValidationError as exc:
        details = "\n".join(
            f"  {'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigError(f"{source} is invalid:\n{details}") from None


@cache
def default_rules() -> RuleSet:
    text = (files("blink_visual.rules") / "default_rules.yaml").read_text(encoding="utf-8")
    return parse_rules(yaml.safe_load(text), source="default_rules.yaml")


def load_rules(path: Path) -> RuleSet:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"rules file not found: {path}") from None
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from None
    return parse_rules(data, source=str(path))


class RuleEngine:
    def __init__(self, extra: Sequence[Rule] = ()) -> None:
        self.rules: list[Rule] = [*extra, *default_rules().rules]

    @classmethod
    def for_file(cls, path: Path | None) -> RuleEngine:
        return cls(load_rules(path).rules if path is not None else ())

    def match(self, finding: Finding) -> Rule | None:
        for rule in self.rules:
            if rule.matches(finding):
                return rule
        return None

    def grade(self, finding: Finding) -> Finding:
        rule = self.match(finding)
        if rule is None:
            return finding.graded(
                Severity.MEDIUM,
                "No rule matched this change; review it manually and add a rule for it.",
                UNMATCHED_RULE,
            )
        return finding.graded(Severity.parse(rule.severity), rule.why.strip(), rule.id)

    def grade_all(self, findings: Iterable[Finding]) -> list[Finding]:
        return [self.grade(f) for f in findings]


__all__ = ["SEVERITY_LABELS", "Rule", "RuleEngine", "RuleSet", "default_rules", "load_rules"]
