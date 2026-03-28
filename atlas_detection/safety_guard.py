"""ATLAS Safety Guard — FR-ATL-006.

Enforces the invariant that safety-relevant ATLAS detections CANNOT be
classified as false positives.  Any attempt to mark such an investigation
as FP is blocked and emitted as a HIGH-severity audit event.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SafetyGuardResult:
    """Result of a safety-guard check on an FP candidate."""

    allowed: bool
    reason: str | None = None
    atlas_technique: str | None = None


class ATLASSafetyGuard:
    """Prevents safety-relevant ATLAS detections from being suppressed as false positives.

    FR-ATL-006: The safety constraint is enforced by querying the
    ``atlas_detections`` table.  If any detection linked to the given
    investigation carries ``safety_relevant = TRUE``, the FP attempt is
    blocked and a HIGH-severity audit event is emitted.
    """

    async def validate_fp_candidate(
        self,
        investigation_id: str,
        pg_pool: Any,
    ) -> SafetyGuardResult:
        """Check whether an investigation may be marked as a false positive.

        Queries ``atlas_detections`` joined to ``investigation_state`` for
        the given investigation.  If any linked detection has
        ``safety_relevant = TRUE`` the candidate is rejected.

        Args:
            investigation_id: The investigation to validate.
            pg_pool: Async Postgres connection pool / client exposing
                     ``fetch_one(query, *params)``.

        Returns:
            :class:`SafetyGuardResult` where ``allowed=False`` indicates
            the investigation MUST NOT be classified as a false positive.
        """
        try:
            row = await pg_pool.fetch_one(
                """
                SELECT ad.atlas_technique, ad.rule_id
                FROM atlas_detections ad
                WHERE ad.investigation_id = $1
                  AND ad.safety_relevant = TRUE
                LIMIT 1
                """,
                investigation_id,
            )
        except Exception as exc:
            # Fail-safe: if the query errors, block the FP to avoid suppressing
            # a potentially safety-critical alert due to a transient DB issue.
            logger.error(
                "ATLASSafetyGuard DB query failed for investigation %s: %s",
                investigation_id, exc,
            )
            return SafetyGuardResult(
                allowed=False,
                reason=(
                    "Safety check unavailable — FP classification blocked to "
                    "protect safety-critical alerts (DB error)."
                ),
            )

        if row is None:
            # No safety-relevant detections linked — FP classification is permitted.
            return SafetyGuardResult(allowed=True)

        atlas_technique = row.get("atlas_technique", "")
        rule_id = row.get("rule_id", "")
        return SafetyGuardResult(
            allowed=False,
            reason=(
                f"Investigation {investigation_id} is linked to a safety-relevant "
                f"ATLAS detection (rule: {rule_id}, technique: {atlas_technique}). "
                "Safety-critical alerts cannot be classified as false positives."
            ),
            atlas_technique=atlas_technique or None,
        )

    async def audit_blocked_attempt(
        self,
        investigation_id: str,
        actor_id: str,
        audit_producer: Any,
    ) -> None:
        """Emit a HIGH-severity audit event when an FP attempt is blocked.

        Uses event_type ``fp.safety_block`` from :class:`EventTaxonomy`.
        Failures are swallowed — audit emission must never prevent the
        guard from returning its decision to the caller.

        Args:
            investigation_id: The investigation that was blocked.
            actor_id: The user or service that attempted the FP classification.
            audit_producer: An :class:`~shared.audit.producer.AuditProducer`
                            instance.
        """
        if audit_producer is None:
            return
        try:
            audit_producer.emit(
                tenant_id="system",
                event_type="fp.safety_block",
                event_category="security",
                severity="HIGH",
                actor_type="user",
                actor_id=actor_id,
                investigation_id=investigation_id,
                context={
                    "blocked_action": "fp_classification",
                    "reason": "safety_relevant_detection",
                },
            )
        except Exception:
            logger.warning(
                "ATLASSafetyGuard: audit emit failed for blocked FP on %s",
                investigation_id,
                exc_info=True,
            )
