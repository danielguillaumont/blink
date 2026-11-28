"""The detector protocol and the context every detector receives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Protocol

from ..capture.models import Snapshot, origin_of
from ..config import TargetConfig
from ..findings import Finding
from ..store import Store

if TYPE_CHECKING:
    from ..inventory import Inventory


@dataclass(frozen=True)
class DetectionContext:
    baseline: Snapshot
    current: Snapshot
    target: TargetConfig
    store: Store
    now: datetime
    inventory: Inventory | None = None

    @property
    def page_origin(self) -> str | None:
        return origin_of(self.current.final_url or self.current.url)

    def put_evidence(self, data: bytes, media_type: str) -> str:
        return self.store.put_blob(data, media_type)


class Detector(Protocol):
    """Compares a baseline snapshot with a current one and reports ungraded findings."""

    name: str

    def detect(self, ctx: DetectionContext) -> list[Finding]: ...
