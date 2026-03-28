"""FP Pattern Generator — Story 10.4.

Analyses closed investigations marked as false_positive to generate
FP pattern candidates for analyst review. Runs as a batch job.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from batch_scheduler.models import BatchTask, BatchTaskType

logger = logging.getLogger(__name__)

# System prompt for the LLM to generate FP patterns
FP_GENERATION_SYSTEM_PROMPT = (
    "You are a security analyst pattern generator. Analyse the closed "
    "false-positive investigations provided and identify common patterns. "
    "For each pattern, output a JSON object with these fields:\n"
    '  "alert_name": the alert rule name,\n'
    '  "alert_name_regex": a regex to match similar alert names,\n'
    '  "entity_patterns": list of {type, value_regex} patterns,\n'
    '  "severity": the common severity level,\n'
    '  "confidence": how confident the pattern is (0-1),\n'
    '  "reason": why this is a false positive pattern.\n'
    "Output a JSON array of pattern objects. Only include high-confidence "
    "patterns (confidence >= 0.8)."
)

PLAYBOOK_GENERATION_SYSTEM_PROMPT = (
    "You are a security playbook generator. Analyse the resolved "
    "investigations provided and generate a remediation playbook. "
    "Output a JSON object with these fields:\n"
    '  "name": short playbook name,\n'
    '  "description": what this playbook addresses,\n'
    '  "tactics": list of MITRE tactics involved,\n'
    '  "techniques": list of technique IDs,\n'
    '  "remediation_steps": ordered list of response steps,\n'
    '  "confidence": how applicable this playbook is (0-1).\n'
    "Focus on actionable, specific remediation steps."
)

MIN_INVESTIGATIONS_FOR_FP = 3
MIN_INVESTIGATIONS_FOR_PLAYBOOK = 2
DEFAULT_LOOKBACK_DAYS = 30


class FPPatternGenerator:
    """Generates FP pattern and playbook batch tasks from closed investigations."""

    def __init__(
        self,
        postgres_client: Any,
        lookback_days: int = DEFAULT_LOOKBACK_DAYS,
    ) -> None:
        self._db = postgres_client
        self._lookback = timedelta(days=lookback_days)

    async def generate_fp_tasks(
        self, now: datetime | None = None
    ) -> list[BatchTask]:
        """Query closed FP investigations and create batch tasks.

        Groups investigations by alert_name and creates a batch task
        for each group with >= MIN_INVESTIGATIONS_FOR_FP members.
        """
        now = now or datetime.now(timezone.utc)
        start = now - self._lookback

        # FR-ATL-006 Safety constraint: exclude investigations whose linked
        # ATLAS detection is safety_relevant=TRUE.  Such detections must never
        # be suppressed as false positives — joining against atlas_detections
        # and filtering at the SQL layer guarantees the LLM batch job never
        # receives them, providing defence-in-depth alongside the HTTP-layer
        # guard in ATLASSafetyGuard.validate_fp_candidate().
        rows = await self._db.fetch_many(
            """
            SELECT i.investigation_id, i.alert_id, i.graphstate_json, i.decision_chain
            FROM investigations i
            WHERE i.state = 'closed'
              AND i.updated_at >= $1 AND i.updated_at < $2
              AND NOT EXISTS (
                  SELECT 1
                  FROM atlas_detections ad
                  WHERE ad.investigation_id = i.investigation_id
                    AND ad.safety_relevant = TRUE
              )
            """,
            start, now,
        )

        # Filter for FP classifications and group by alert pattern
        fp_groups: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            gs = row.get("graphstate_json", {})
            if isinstance(gs, str):
                try:
                    gs = json.loads(gs)
                except json.JSONDecodeError:
                    continue

            classification = gs.get("classification", "")
            if classification != "false_positive":
                continue

            alert_title = gs.get("alert_title", row.get("alert_id", "unknown"))
            # Group by alert name prefix (first 50 chars as key)
            group_key = alert_title[:50] if alert_title else "unknown"
            fp_groups.setdefault(group_key, []).append({
                "investigation_id": row["investigation_id"],
                "alert_id": row.get("alert_id", ""),
                "alert_title": alert_title,
                "entities": gs.get("entities", {}),
                "decision_chain": row.get("decision_chain", []),
            })

        tasks: list[BatchTask] = []
        for group_key, investigations in fp_groups.items():
            if len(investigations) < MIN_INVESTIGATIONS_FOR_FP:
                continue

            user_content = json.dumps({
                "alert_group": group_key,
                "investigation_count": len(investigations),
                "investigations": investigations[:20],  # cap context size
            })

            investigation_ids = [inv["investigation_id"] for inv in investigations]
            tasks.append(BatchTask(
                task_type=BatchTaskType.FP_PATTERN_GENERATION.value,
                system_prompt=FP_GENERATION_SYSTEM_PROMPT,
                user_content=user_content,
                metadata={
                    "task_type": BatchTaskType.FP_PATTERN_GENERATION.value,
                    "source_investigations": investigation_ids[:20],
                    "alert_group": group_key,
                },
            ))

        logger.info(
            "Generated %d FP pattern tasks from %d investigation groups",
            len(tasks), len(fp_groups),
        )
        return tasks

    async def generate_playbook_tasks(
        self, now: datetime | None = None
    ) -> list[BatchTask]:
        """Query resolved investigations and create playbook generation tasks.

        Groups by primary technique and generates tasks for groups
        with >= MIN_INVESTIGATIONS_FOR_PLAYBOOK members.
        """
        now = now or datetime.now(timezone.utc)
        start = now - self._lookback

        rows = await self._db.fetch_many(
            """
            SELECT investigation_id, alert_id, graphstate_json, decision_chain
            FROM investigations
            WHERE state = 'closed'
              AND updated_at >= $1 AND updated_at < $2
            """,
            start, now,
        )

        # Group by primary technique
        technique_groups: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            gs = row.get("graphstate_json", {})
            if isinstance(gs, str):
                try:
                    gs = json.loads(gs)
                except json.JSONDecodeError:
                    continue

            classification = gs.get("classification", "")
            if classification == "false_positive":
                continue

            techniques = gs.get("atlas_techniques", [])
            if not techniques:
                techniques = gs.get("techniques", [])
            if not techniques:
                continue

            # Use first technique as group key
            primary = techniques[0] if isinstance(techniques[0], str) else techniques[0].get("atlas_id", "")
            technique_groups.setdefault(primary, []).append({
                "investigation_id": row["investigation_id"],
                "alert_id": row.get("alert_id", ""),
                "classification": classification,
                "techniques": techniques,
                "decision_chain": row.get("decision_chain", []),
            })

        tasks: list[BatchTask] = []
        for technique, investigations in technique_groups.items():
            if len(investigations) < MIN_INVESTIGATIONS_FOR_PLAYBOOK:
                continue

            user_content = json.dumps({
                "primary_technique": technique,
                "investigation_count": len(investigations),
                "investigations": investigations[:20],
            })

            investigation_ids = [inv["investigation_id"] for inv in investigations]
            tasks.append(BatchTask(
                task_type=BatchTaskType.PLAYBOOK_GENERATION.value,
                system_prompt=PLAYBOOK_GENERATION_SYSTEM_PROMPT,
                user_content=user_content,
                metadata={
                    "task_type": BatchTaskType.PLAYBOOK_GENERATION.value,
                    "source_investigations": investigation_ids[:20],
                    "primary_technique": technique,
                },
            ))

        logger.info(
            "Generated %d playbook tasks from %d technique groups",
            len(tasks), len(technique_groups),
        )
        return tasks

    async def generate_all_tasks(
        self, now: datetime | None = None
    ) -> list[BatchTask]:
        """Generate both FP pattern and playbook tasks."""
        fp_tasks = await self.generate_fp_tasks(now)
        playbook_tasks = await self.generate_playbook_tasks(now)
        return fp_tasks + playbook_tasks
