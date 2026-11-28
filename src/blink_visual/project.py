"""A Blink project: ``blink.yaml``, its evidence store and its inventory."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .config import CONFIG_FILENAME, BlinkConfig, TargetConfig, load_config, parse_config
from .errors import ConfigError
from .store import Store

CONFIG_ENV = "BLINK_CONFIG"


def default_config_path() -> Path:
    return Path(os.environ.get(CONFIG_ENV, CONFIG_FILENAME))


def adhoc_name(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or "target"
    slug = re.sub(r"[^a-z0-9]+", "-", f"{host}-{parts.port or ''}".lower()).strip("-")
    return f"adhoc-{slug}"[:63]


@dataclass(frozen=True)
class Project:
    config_path: Path
    config: BlinkConfig
    exists: bool = True

    @classmethod
    def load(cls, path: Path | None = None, *, required: bool = True) -> Project:
        path = (path or default_config_path()).absolute()
        if not path.exists() and not required:
            return cls(path, parse_config({}), exists=False)
        return cls(path, load_config(path))

    @property
    def root(self) -> Path:
        return self.config_path.parent

    @property
    def store_dir(self) -> Path:
        return (self.root / self.config.store).resolve()

    @property
    def inventory_path(self) -> Path:
        return (self.root / self.config.inventory).resolve()

    def open_store(self) -> Store:
        return Store(self.store_dir)

    def resolve_target(self, spec: str) -> TargetConfig:
        """A configured target by name, or an ad-hoc target for an http(s) URL."""
        if "://" not in spec:
            if not self.exists:
                raise ConfigError(
                    f"no {self.config_path.name} found, so '{spec}' cannot be resolved",
                    hint="pass a full URL, or run `blink init` to create a configuration",
                )
            return self.config.target(spec)
        for target in self.config.targets:
            if target.url == spec:
                return target
        try:
            return TargetConfig(name=adhoc_name(spec), url=spec)
        except ValueError as exc:
            raise ConfigError(f"invalid target URL {spec!r}: {exc}") from None
