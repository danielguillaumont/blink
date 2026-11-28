"""DOM detector: a structural (tree edit) summary of the configured payment region."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from difflib import SequenceMatcher

from bs4.element import NavigableString, Tag

from ..capture.normalize import parse_html
from ..errors import StoreError
from ..findings import Finding
from .base import DetectionContext

SENSITIVE_TAGS = frozenset({"script", "iframe", "frame", "form", "input", "object", "embed"})
MAX_LINES = 25


@dataclass(frozen=True)
class Node:
    depth: int
    signature: str
    tag: str
    attributes: tuple[tuple[str, str], ...]
    text: str


def _signature(tag: Tag) -> str:
    parts = [tag.name]
    if tag.get("id"):
        parts.append(f"#{tag['id']}")
    classes: list[str] = list(tag.get("class") or [])
    if classes:
        parts.append("." + ".".join(sorted(classes)))
    for name in ("name", "type"):
        value = tag.get(name)
        if isinstance(value, str) and value:
            parts.append(f"[{name}={value}]")
    return "".join(parts)


def flatten(region_html: str) -> list[Node]:
    """Pre-order list of elements with depth, identity signature, attributes and own text."""
    soup = parse_html(region_html)
    nodes: list[Node] = []

    def walk(tag: Tag, depth: int) -> None:
        text = " ".join(
            s.strip() for s in tag.children if isinstance(s, NavigableString) and s.strip()
        )
        attributes = tuple(
            sorted(
                (k, " ".join(v) if isinstance(v, list) else str(v)) for k, v in tag.attrs.items()
            )
        )
        nodes.append(Node(depth, _signature(tag), tag.name, attributes, text))
        for child in tag.children:
            if isinstance(child, Tag):
                walk(child, depth + 1)

    for top in soup.children:
        if isinstance(top, Tag):
            walk(top, 0)
    return nodes


@dataclass(frozen=True)
class TreeEdit:
    added: list[Node]
    removed: list[Node]
    attributes_changed: list[Node]
    text_changed: list[Node]

    @property
    def empty(self) -> bool:
        return not (self.added or self.removed or self.attributes_changed or self.text_changed)


def tree_edit(before: list[Node], after: list[Node]) -> TreeEdit:
    key = [f"{n.depth}:{n.signature}" for n in before]
    other = [f"{n.depth}:{n.signature}" for n in after]
    added: list[Node] = []
    removed: list[Node] = []
    attrs: list[Node] = []
    texts: list[Node] = []
    matcher = SequenceMatcher(a=key, b=other, autojunk=False)
    for op, a0, a1, b0, b1 in matcher.get_opcodes():
        if op == "equal":
            for old, new in zip(before[a0:a1], after[b0:b1], strict=True):
                if old.attributes != new.attributes:
                    attrs.append(new)
                if old.text != new.text:
                    texts.append(new)
        else:
            removed.extend(before[a0:a1])
            added.extend(after[b0:b1])
    return TreeEdit(added, removed, attrs, texts)


class DomDetector:
    name = "dom"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        from ..capture.normalize import extract_region

        selector = ctx.target.payment_region
        if not selector:
            return []
        try:
            before_dom = ctx.store.get_blob(ctx.baseline.blobs["dom"]).decode("utf-8")
            after_dom = ctx.store.get_blob(ctx.current.blobs["dom"]).decode("utf-8")
        except (KeyError, StoreError):
            return []
        before = extract_region(before_dom, selector)
        after = extract_region(after_dom, selector)
        if before is None:
            return []
        if after is None:
            return [
                Finding(
                    detector=self.name,
                    change_type="region_missing",
                    subject=selector,
                    title=f"Payment region {selector!r} is no longer on the page",
                    evidence={"selector": selector},
                )
            ]
        edit = tree_edit(flatten(before), flatten(after))
        if edit.empty:
            return []
        added_tags = Counter(n.tag for n in edit.added)
        sensitive = sum(added_tags[t] for t in SENSITIVE_TAGS)
        lines = [f"+ {'  ' * n.depth}{n.signature}" for n in edit.added]
        lines += [f"- {'  ' * n.depth}{n.signature}" for n in edit.removed]
        lines += [f"~ {'  ' * n.depth}{n.signature} (attributes)" for n in edit.attributes_changed]
        lines += [f"~ {'  ' * n.depth}{n.signature} (text)" for n in edit.text_changed]
        summary = ", ".join(f"{count} {tag}" for tag, count in sorted(added_tags.items()))
        return [
            Finding(
                detector=self.name,
                change_type="region_changed",
                subject=selector,
                title=f"Payment region structure changed: +{len(edit.added)} "
                f"-{len(edit.removed)} ~{len(edit.attributes_changed) + len(edit.text_changed)}",
                attributes={
                    "added": len(edit.added),
                    "removed": len(edit.removed),
                    "attributes_changed": len(edit.attributes_changed),
                    "text_changed": len(edit.text_changed),
                    "sensitive_added": sensitive,
                },
                evidence={
                    "selector": selector,
                    "added_elements": summary,
                    "edits": lines[:MAX_LINES],
                    "truncated": len(lines) > MAX_LINES,
                    "before_blob": ctx.put_evidence(before.encode("utf-8"), "text/html"),
                    "after_blob": ctx.put_evidence(after.encode("utf-8"), "text/html"),
                },
            )
        ]
