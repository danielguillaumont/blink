"""Capture configured targets and persist snapshot bundles."""

from __future__ import annotations

from collections.abc import Sequence

from ..config import TargetConfig
from ..project import Project
from ..store import Store
from .browser import Capturer
from .models import Snapshot


def capture_target(
    project: Project,
    target: TargetConfig,
    store: Store,
    *,
    profiles: Sequence[str] | None = None,
    capturer: Capturer | None = None,
) -> list[Snapshot]:
    """Capture ``target`` once per profile and save each snapshot to ``store``."""
    names = list(profiles or target.profiles)
    if capturer is None:
        with Capturer() as owned:
            return capture_target(project, target, store, profiles=names, capturer=owned)
    snapshots = []
    for name in names:
        snapshot = capturer.capture(target, name, project.config.profile(name), store)
        store.save_snapshot(snapshot)
        snapshots.append(snapshot)
    return snapshots
