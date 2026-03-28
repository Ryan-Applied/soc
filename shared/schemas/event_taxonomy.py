"""Audit event taxonomy — Story 13.1.

Defines :class:`EventCategory` and :class:`EventTaxonomy` enums plus
the :data:`EVENT_CATEGORY_MAP` mapping every event type to its category.
"""

from __future__ import annotations

from enum import Enum


class EventCategory(str, Enum):
    """Top-level audit event categories."""

    DECISION = "decision"
    ACTION = "action"
    APPROVAL = "approval"
    SECURITY = "security"
    SYSTEM = "system"


class EventTaxonomy(str, Enum):
    """Controlled vocabulary of audit event types (~40 types)."""

    # Decision events (12)
    ALERT_CLASSIFIED = "alert.classified"
    ALERT_AUTO_CLOSED = "alert.auto_closed"
    ALERT_ESCALATED = "alert.escalated"
    ALERT_SHORT_CIRCUITED = "alert.short_circuited"
    INVESTIGATION_STATE_CHANGED = "investigation.state_changed"
    INVESTIGATION_ENRICHED = "investigation.enriched"
    PLAYBOOK_SELECTED = "playbook.selected"
    PLAYBOOK_GENERATED = "playbook.generated"
    CTEM_EXPOSURE_SCORED = "ctem.exposure_scored"
    ATLAS_DETECTION_FIRED = "atlas.detection_fired"
    ROUTING_TIER_SELECTED = "routing.tier_selected"
    ROUTING_PROVIDER_FAILOVER = "routing.provider_failover"

    # Action events (11)
    RESPONSE_PREPARED = "response.prepared"
    RESPONSE_EXECUTED = "response.executed"
    RESPONSE_ROLLED_BACK = "response.rolled_back"
    IOC_ENRICHED = "ioc.enriched"
    FP_PATTERN_CREATED = "fp_pattern.created"
    FP_PATTERN_ACTIVATED = "fp_pattern.activated"
    CTEM_REMEDIATION_ASSIGNED = "ctem.remediation_assigned"
    CTEM_REMEDIATION_VERIFIED = "ctem.remediation_verified"
    KNOWLEDGE_INDEXED = "knowledge.indexed"
    EMBEDDING_REINDEXED = "embedding.reindexed"
    RESPONSE_GENERATED = "response.generated"

    # Approval events (8)
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_DENIED = "approval.denied"
    APPROVAL_TIMED_OUT = "approval.timed_out"
    APPROVAL_ESCALATED = "approval.escalated"
    FP_PATTERN_APPROVED = "fp_pattern.approved"
    FP_PATTERN_REVOKED = "fp_pattern.revoked"
    SHADOW_GO_LIVE_APPROVED = "shadow.go_live_approved"

    # Security events (8)
    INJECTION_DETECTED = "injection.detected"
    INJECTION_QUARANTINED = "injection.quarantined"
    TECHNIQUE_QUARANTINED = "technique.quarantined"
    ACCUMULATION_THRESHOLD_BREACHED = "accumulation.threshold_breached"
    SPEND_SOFT_LIMIT = "spend.soft_limit"
    SPEND_HARD_LIMIT = "spend.hard_limit"
    # FR-ATL-006: Safety guard — FP attempt blocked on safety-critical alert
    FP_SAFETY_BLOCK = "fp.safety_block"
    # FR-CSM-004: Analyst feedback on investigation outcome
    ANALYST_FEEDBACK_SUBMITTED = "analyst.feedback.submitted"

    # Canary / shadow events (3)
    CANARY_PROMOTED = "canary.promoted"
    CANARY_ROLLED_BACK = "canary.rolled_back"
    SHADOW_DECISION_LOGGED = "shadow.decision_logged"

    # System events (8)
    DEGRADATION_ENTERED = "degradation.entered"
    DEGRADATION_EXITED = "degradation.exited"
    KILL_SWITCH_ACTIVATED = "kill_switch.activated"
    KILL_SWITCH_DEACTIVATED = "kill_switch.deactivated"
    CONFIG_CHANGED = "config.changed"
    CIRCUIT_BREAKER_OPENED = "circuit_breaker.opened"
    CIRCUIT_BREAKER_CLOSED = "circuit_breaker.closed"
    SYSTEM_GENESIS = "system.genesis"


EVENT_CATEGORY_MAP: dict[EventTaxonomy, EventCategory] = {
    # Decision events
    EventTaxonomy.ALERT_CLASSIFIED: EventCategory.DECISION,
    EventTaxonomy.ALERT_AUTO_CLOSED: EventCategory.DECISION,
    EventTaxonomy.ALERT_ESCALATED: EventCategory.DECISION,
    EventTaxonomy.ALERT_SHORT_CIRCUITED: EventCategory.DECISION,
    EventTaxonomy.INVESTIGATION_STATE_CHANGED: EventCategory.DECISION,
    EventTaxonomy.INVESTIGATION_ENRICHED: EventCategory.DECISION,
    EventTaxonomy.PLAYBOOK_SELECTED: EventCategory.DECISION,
    EventTaxonomy.PLAYBOOK_GENERATED: EventCategory.DECISION,
    EventTaxonomy.CTEM_EXPOSURE_SCORED: EventCategory.DECISION,
    EventTaxonomy.ATLAS_DETECTION_FIRED: EventCategory.DECISION,
    EventTaxonomy.ROUTING_TIER_SELECTED: EventCategory.DECISION,
    EventTaxonomy.ROUTING_PROVIDER_FAILOVER: EventCategory.DECISION,
    # Action events
    EventTaxonomy.RESPONSE_PREPARED: EventCategory.ACTION,
    EventTaxonomy.RESPONSE_EXECUTED: EventCategory.ACTION,
    EventTaxonomy.RESPONSE_ROLLED_BACK: EventCategory.ACTION,
    EventTaxonomy.IOC_ENRICHED: EventCategory.ACTION,
    EventTaxonomy.FP_PATTERN_CREATED: EventCategory.ACTION,
    EventTaxonomy.FP_PATTERN_ACTIVATED: EventCategory.ACTION,
    EventTaxonomy.CTEM_REMEDIATION_ASSIGNED: EventCategory.ACTION,
    EventTaxonomy.CTEM_REMEDIATION_VERIFIED: EventCategory.ACTION,
    EventTaxonomy.KNOWLEDGE_INDEXED: EventCategory.ACTION,
    EventTaxonomy.EMBEDDING_REINDEXED: EventCategory.ACTION,
    EventTaxonomy.RESPONSE_GENERATED: EventCategory.ACTION,
    # Approval events
    EventTaxonomy.APPROVAL_REQUESTED: EventCategory.APPROVAL,
    EventTaxonomy.APPROVAL_GRANTED: EventCategory.APPROVAL,
    EventTaxonomy.APPROVAL_DENIED: EventCategory.APPROVAL,
    EventTaxonomy.APPROVAL_TIMED_OUT: EventCategory.APPROVAL,
    EventTaxonomy.APPROVAL_ESCALATED: EventCategory.APPROVAL,
    EventTaxonomy.FP_PATTERN_APPROVED: EventCategory.APPROVAL,
    EventTaxonomy.FP_PATTERN_REVOKED: EventCategory.APPROVAL,
    EventTaxonomy.SHADOW_GO_LIVE_APPROVED: EventCategory.APPROVAL,
    # Security events
    EventTaxonomy.INJECTION_DETECTED: EventCategory.SECURITY,
    EventTaxonomy.INJECTION_QUARANTINED: EventCategory.SECURITY,
    EventTaxonomy.TECHNIQUE_QUARANTINED: EventCategory.SECURITY,
    EventTaxonomy.ACCUMULATION_THRESHOLD_BREACHED: EventCategory.SECURITY,
    EventTaxonomy.SPEND_SOFT_LIMIT: EventCategory.SECURITY,
    EventTaxonomy.SPEND_HARD_LIMIT: EventCategory.SECURITY,
    EventTaxonomy.FP_SAFETY_BLOCK: EventCategory.SECURITY,
    EventTaxonomy.ANALYST_FEEDBACK_SUBMITTED: EventCategory.ACTION,
    # Canary / shadow events
    EventTaxonomy.CANARY_PROMOTED: EventCategory.DECISION,
    EventTaxonomy.CANARY_ROLLED_BACK: EventCategory.DECISION,
    EventTaxonomy.SHADOW_DECISION_LOGGED: EventCategory.DECISION,
    # System events
    EventTaxonomy.DEGRADATION_ENTERED: EventCategory.SYSTEM,
    EventTaxonomy.DEGRADATION_EXITED: EventCategory.SYSTEM,
    EventTaxonomy.KILL_SWITCH_ACTIVATED: EventCategory.SYSTEM,
    EventTaxonomy.KILL_SWITCH_DEACTIVATED: EventCategory.SYSTEM,
    EventTaxonomy.CONFIG_CHANGED: EventCategory.SYSTEM,
    EventTaxonomy.CIRCUIT_BREAKER_OPENED: EventCategory.SYSTEM,
    EventTaxonomy.CIRCUIT_BREAKER_CLOSED: EventCategory.SYSTEM,
    EventTaxonomy.SYSTEM_GENESIS: EventCategory.SYSTEM,
}
