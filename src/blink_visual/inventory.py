"""The PCI DSS 6.4.3 script inventory: ``blink.inventory.yaml``, committed to the user's repo.

Each entry records what the script is (URL or inline digest, first-party, third-party or
inline), how its integrity is checked (an expected SHA-384, or ``dynamic`` for scripts whose
content legitimately changes, plus the SRI value used on the page) and how it was authorized
(justification, owner, approver and time). Unapproved scripts are findings on every scan.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .capture.models import ScriptRecord, origin_of
from .errors import BlinkError, ConfigError

DYNAMIC = "dynamic"
HEADER = (
    "# Blink script inventory (PCI DSS 6.4.3). Commit this file and review changes to it.\n"
    "# Each script needs a justification, an owner and an approval (`blink approve`).\n"
    "# expected_hash is the SRI-style SHA-384 of the content, or 'dynamic' for scripts whose\n"
    "# content legitimately changes (their URL is still authorized, their hash is not pinned).\n"
)
ScriptType = Literal["first-party", "third-party", "inline"]
_ID = r"^[a-z0-9][a-z0-9-]{0,79}$"


class InventoryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=_ID)
    type: ScriptType
    url: str | None = None
    url_pattern: str | None = None
    """Optional regular expression (full match) for URLs with rotating query strings."""
    inline_sha384: str | None = None
    expected_hash: str = DYNAMIC
    sri: str | None = None
    justification: str = ""
    owner: str = ""
    approved_by: str = ""
    approved_at: str | None = None
    notes: str = ""

    @field_validator("url_pattern")
    @classmethod
    def _regex(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid regular expression: {exc}") from None
        return value

    @field_validator("expected_hash")
    @classmethod
    def _hash(cls, value: str) -> str:
        if value != DYNAMIC and not value.startswith("sha384-"):
            raise ValueError("must be 'dynamic' or an SRI-style 'sha384-<base64>' digest")
        return value

    @property
    def approved(self) -> bool:
        return bool(self.approved_by and self.approved_at and self.justification and self.owner)

    @property
    def pinned(self) -> bool:
        return self.expected_hash != DYNAMIC

    def matches(self, script: ScriptRecord) -> bool:
        if script.inline:
            return self.inline_sha384 is not None and self.inline_sha384 == script.sha384
        if script.url is None:
            return False
        if self.url is not None and self.url == script.url:
            return True
        return (
            self.url_pattern is not None and re.fullmatch(self.url_pattern, script.url) is not None
        )


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    scripts: list[InventoryEntry] = Field(default_factory=list)

    def match(self, script: ScriptRecord) -> InventoryEntry | None:
        for entry in self.scripts:
            if entry.matches(script):
                return entry
        return None

    def get(self, entry_id: str) -> InventoryEntry | None:
        return next((e for e in self.scripts if e.id == entry_id), None)

    def upsert(self, entry: InventoryEntry) -> None:
        for index, existing in enumerate(self.scripts):
            if existing.id == entry.id:
                self.scripts[index] = entry
                return
        self.scripts.append(entry)


def script_type(script: ScriptRecord, page_url: str) -> ScriptType:
    if script.inline:
        return "inline"
    return "first-party" if script.origin == origin_of(page_url) else "third-party"


def suggested_id(script: ScriptRecord) -> str:
    """A stable, readable id derived from the URL (or the inline digest)."""
    if script.inline or script.url is None:
        digest = hashlib.sha256((script.sha384 or "").encode()).hexdigest()
        return f"inline-{digest[:12]}"
    slug = re.sub(r"[^a-z0-9]+", "-", re.sub(r"^[a-z]+://", "", script.url.lower())).strip("-")
    if len(slug) > 64:
        slug = f"{slug[:51]}-{hashlib.sha256(script.url.encode()).hexdigest()[:12]}"
    return slug or "script"


def entry_for(script: ScriptRecord, page_url: str) -> InventoryEntry:
    """An unapproved entry describing ``script`` as captured."""
    kind = script_type(script, page_url)
    return InventoryEntry(
        id=suggested_id(script),
        type=kind,
        url=None if script.inline else script.url,
        inline_sha384=script.sha384 if script.inline else None,
        expected_hash=script.sha384 or DYNAMIC,
        sri=script.integrity,
    )


def parse_inventory(data: object, *, source: str) -> Inventory:
    try:
        return Inventory.model_validate(data if data is not None else {})
    except ValidationError as exc:
        details = "\n".join(
            f"  {'.'.join(str(p) for p in e['loc'])}: {e['msg'].removeprefix('Value error, ')}"
            for e in exc.errors()
        )
        raise ConfigError(f"{source} is invalid:\n{details}") from None


def load_inventory(path: Path) -> Inventory | None:
    """The inventory at ``path``, or ``None`` when the project has no inventory file."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from None
    inventory = parse_inventory(data, source=str(path))
    ids = [e.id for e in inventory.scripts]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ConfigError(f"{path}: duplicate script ids: {', '.join(duplicates)}")
    return inventory


def save_inventory(path: Path, inventory: Inventory) -> None:
    data = inventory.model_dump(mode="json")
    text = HEADER + yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)
    temp = path.with_name(f".{path.name}.tmp")
    temp.write_text(text, encoding="utf-8", newline="\n")
    temp.replace(path)


def approve(
    entry: InventoryEntry,
    *,
    justification: str,
    owner: str,
    approved_by: str,
    dynamic: bool = False,
    notes: str | None = None,
    now: datetime | None = None,
) -> InventoryEntry:
    for name, value in (("justification", justification), ("owner", owner)):
        if not value.strip():
            raise BlinkError(f"--{name} must not be empty; PCI DSS 6.4.3 requires it")
    if not approved_by.strip():
        raise BlinkError("--approved-by must not be empty")
    moment = (now or datetime.now(UTC)).isoformat(timespec="seconds").replace("+00:00", "Z")
    update: dict[str, object] = {
        "justification": justification.strip(),
        "owner": owner.strip(),
        "approved_by": approved_by.strip(),
        "approved_at": moment,
    }
    if dynamic:
        update["expected_hash"] = DYNAMIC
    if notes is not None:
        update["notes"] = notes
    return entry.model_copy(update=update)


def unique_scripts(
    scripts: Iterable[tuple[ScriptRecord, str]],
) -> list[tuple[ScriptRecord, str]]:
    """Deduplicate (script, page_url) pairs by script key, keeping the first."""
    seen: dict[str, tuple[ScriptRecord, str]] = {}
    for script, page in scripts:
        if script.is_javascript:
            seen.setdefault(script.key, (script, page))
    return list(seen.values())
