"""Inventory detector (PCI DSS 6.4.3): unapproved scripts and pinned-hash violations.

Unlike the other detectors this is a policy check on the current snapshot: a script that is
not approved in ``blink.inventory.yaml`` is a finding even if it was already in the baseline.
"""

from __future__ import annotations

from ..findings import Finding
from ..inventory import script_type, suggested_id
from .base import DetectionContext


class InventoryDetector:
    name = "inventory"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        inventory = ctx.inventory
        if inventory is None:
            return []
        in_baseline = {s.key for s in ctx.baseline.scripts}
        page = ctx.current.final_url or ctx.current.url
        findings: list[Finding] = []
        for script in ctx.current.scripts:
            if not script.is_javascript:
                continue
            entry = inventory.match(script)
            kind = script_type(script, page)
            if entry is None or not entry.approved:
                inventory_id = entry.id if entry else suggested_id(script)
                findings.append(
                    Finding(
                        detector=self.name,
                        change_type="unapproved",
                        subject=script.key,
                        title=f"Script is not approved in the inventory: {script.key[:120]}",
                        attributes={
                            "in_baseline": script.key in in_baseline,
                            "listed": entry is not None,
                            "type": kind,
                        },
                        evidence={
                            "inventory_id": inventory_id,
                            "url": script.url,
                            "sha384": script.sha384,
                            "blob": script.sha256,
                            "approve": f"blink approve {inventory_id} "
                            '--justification "..." --owner "..."',
                        },
                    )
                )
            elif entry.pinned and script.sha384 and script.sha384 != entry.expected_hash:
                findings.append(
                    Finding(
                        detector=self.name,
                        change_type="hash_mismatch",
                        subject=script.key,
                        title=f"Approved script content changed: {entry.id}",
                        attributes={"type": kind},
                        evidence={
                            "inventory_id": entry.id,
                            "expected_sha384": entry.expected_hash,
                            "actual_sha384": script.sha384,
                            "blob": script.sha256,
                            "approved_by": entry.approved_by,
                            "approved_at": entry.approved_at,
                        },
                    )
                )
        return findings
