"""Test data placeholders for journeys: ``{{canary.pan}}``, ``{{faker.email}}``, ``{{env.X}}``.

Templates are validated when the config loads and resolved at capture time. Only templates
are ever recorded in snapshots; resolved values (which may come from secret environment
variables) are not.
"""

from __future__ import annotations

import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field

from ..canary import CANARY_FIELDS, Canary
from ..errors import ConfigError

PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]+)\.([A-Za-z0-9_]+)\s*\}\}")
NAMESPACES = ("canary", "faker", "env", "test_data")

_FIRST = ("Alex", "Sam", "Robin", "Jamie", "Charlie", "Morgan", "Kim", "Noor")
_LAST = ("Jansen", "de Vries", "Smith", "Garcia", "Nowak", "Rossi", "Okafor", "Lee")
_CITY = ("Utrecht", "Leeds", "Porto", "Lyon", "Gdansk", "Bergen")
FAKER_FIELDS = (
    "email",
    "first_name",
    "last_name",
    "name",
    "phone",
    "street",
    "city",
    "postcode",
    "country",
)


def fake(name: str) -> str:
    """A plausible, obviously synthetic value (no third-party faker dependency)."""
    token = secrets.token_hex(3)
    first, last = secrets.choice(_FIRST), secrets.choice(_LAST)
    values = {
        "email": f"test-{token}@example.com",
        "first_name": first,
        "last_name": last,
        "name": f"{first} {last}",
        "phone": f"+31 6 {secrets.randbelow(10**8):08d}",
        "street": f"Teststraat {1 + secrets.randbelow(200)}",
        "city": secrets.choice(_CITY),
        "postcode": f"{1000 + secrets.randbelow(9000)} AB",
        "country": "NL",
    }
    return values[name]


def placeholders(text: str) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in PLACEHOLDER.finditer(text)]


def check_template(text: str, test_data_keys: set[str] | None) -> None:
    """Raise ``ValueError`` for an unknown placeholder. ``None`` keys: test_data not allowed."""
    for namespace, key in placeholders(text):
        if namespace == "canary" and key not in CANARY_FIELDS:
            raise ValueError(f"unknown canary field '{key}' (known: {', '.join(CANARY_FIELDS)})")
        if namespace == "faker" and key not in FAKER_FIELDS:
            raise ValueError(f"unknown faker field '{key}' (known: {', '.join(FAKER_FIELDS)})")
        if namespace == "test_data":
            if test_data_keys is None:
                raise ValueError("test_data values cannot refer to other test_data values")
            if key not in test_data_keys:
                raise ValueError(f"unknown test_data key '{key}'")
        if namespace == "env" and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ValueError(f"invalid environment variable name '{key}'")
        if namespace not in NAMESPACES:
            raise ValueError(
                f"unknown placeholder '{{{{{namespace}.{key}}}}}' "
                f"(namespaces: {', '.join(NAMESPACES)})"
            )
    if "{{" in PLACEHOLDER.sub("", text):
        raise ValueError(f"malformed placeholder in {text!r}; use {{{{namespace.key}}}}")


@dataclass
class Resolver:
    """Resolves templates for one capture: one canary, stable faker values, env secrets."""

    test_data: Mapping[str, str]
    target: str
    canary: Canary = field(default_factory=Canary.generate)
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ)
    secrets_used: set[str] = field(default_factory=set)
    _fakes: dict[str, str] = field(default_factory=dict)

    def _value(self, namespace: str, key: str, depth: int) -> str:
        if namespace == "canary":
            return self.canary.values()[key]
        if namespace == "faker":
            return self._fakes.setdefault(key, fake(key))
        if namespace == "env":
            value = self.environ.get(key, "")
            if not value:
                raise ConfigError(
                    f"journey of target '{self.target}' needs environment variable {key}, "
                    "which is not set",
                    hint=f"export {key}=... (from your secret store) before running Blink",
                )
            self.secrets_used.add(value)
            return value
        if depth > 0:  # pragma: no cover - rejected at config load
            raise ConfigError("test_data values cannot refer to other test_data values")
        return self.resolve(self.test_data[key], depth=1)

    def resolve(self, text: str, *, depth: int = 0) -> str:
        return PLACEHOLDER.sub(lambda m: self._value(m.group(1), m.group(2), depth), text)
