"""DOM normalization: remove volatile values so equal pages hash equally.

Pure functions over serialized HTML. Rules come from ``normalize:`` in ``blink.yaml``:

- ``remove``: elements deleted entirely (for example third-party chat bubbles).
- ``strip_attributes``: attributes deleted everywhere (``nonce`` by default).
- ``volatile_attributes``: attribute values replaced by a marker on matching elements
  (for example a CSRF token in ``input[name=csrf_token]``).
- ``volatile_text``: text inside matching elements replaced by a marker (timestamps, promos).
- ``regexes``: applied last, to the serialized document.

Structure is preserved: a volatile attribute keeps its name and a volatile element keeps
its children, so structural changes are still visible to the DOM detector.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from bs4 import BeautifulSoup
from bs4.element import Comment, NavigableString, Tag
from soupsieve import SelectorSyntaxError

from ..config import NormalizeConfig
from ..errors import ConfigError

VOLATILE = "[volatile]"


def _select(soup: BeautifulSoup | Tag, selector: str) -> Iterable[Tag]:
    try:
        return list(soup.select(selector))
    except (SelectorSyntaxError, ValueError, NotImplementedError) as exc:
        raise ConfigError(f"invalid CSS selector {selector!r}: {exc}") from None


def parse_html(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


def normalize_soup(soup: BeautifulSoup, config: NormalizeConfig) -> BeautifulSoup:
    for selector in config.remove:
        for element in _select(soup, selector):
            element.decompose()
    if config.strip_attributes:
        strip = set(config.strip_attributes)
        for element in soup.find_all(True):
            for name in strip & set(element.attrs):
                del element.attrs[name]
    for rule in config.volatile_attributes:
        for element in _select(soup, rule.selector):
            for name in rule.attributes:
                if name in element.attrs:
                    element.attrs[name] = VOLATILE
    for selector in config.volatile_text:
        for element in _select(soup, selector):
            strings = [
                s
                for s in element.descendants
                if isinstance(s, NavigableString) and not isinstance(s, Comment)
            ]
            for string in strings:
                string.replace_with("")
            element.insert(0, NavigableString(VOLATILE))
    return soup


def apply_regexes(text: str, config: NormalizeConfig) -> str:
    for rule in config.regexes:
        text = re.sub(rule.pattern, rule.replacement, text)
    return text


def normalize_dom(html: str, config: NormalizeConfig) -> str:
    """Return the normalized serialization of ``html``."""
    soup = normalize_soup(parse_html(html), config)
    return apply_regexes(str(soup), config)


def dom_hash(normalized: str) -> str:
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def extract_region(normalized_html: str, selector: str) -> str | None:
    """Serialized outer HTML of the first element matching ``selector``, if any."""
    soup = parse_html(normalized_html)
    matches = list(_select(soup, selector))
    return str(matches[0]) if matches else None
