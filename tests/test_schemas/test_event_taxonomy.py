"""Tests for EventCategory, EventTaxonomy, and EVENT_CATEGORY_MAP — Story 13.1."""

from shared.schemas.event_taxonomy import (
    EVENT_CATEGORY_MAP,
    EventCategory,
    EventTaxonomy,
)


class TestEventTaxonomy:
    """AC-2: EventTaxonomy enum with ~40 event types across 5 categories."""

    def test_all_values_are_valid_strings(self):
        for member in EventTaxonomy:
            assert isinstance(member.value, str)
            assert "." in member.value, f"{member.name} must use dotted notation"

    def test_minimum_40_event_types(self):
        assert len(EventTaxonomy) >= 40

    def test_no_duplicate_values(self):
        values = [m.value for m in EventTaxonomy]
        assert len(values) == len(set(values)), "Duplicate values found"

    def test_enum_is_str_based(self):
        assert isinstance(EventTaxonomy.ALERT_CLASSIFIED, str)
        assert EventTaxonomy.ALERT_CLASSIFIED == "alert.classified"

    def test_category_map_covers_all_events(self):
        mapped = set(EVENT_CATEGORY_MAP.keys())
        all_events = set(EventTaxonomy)
        assert mapped == all_events, f"Missing mappings: {all_events - mapped}"

    def test_five_categories_represented(self):
        categories = set(EVENT_CATEGORY_MAP.values())
        assert categories == set(EventCategory)

    def test_decision_events_count(self):
        count = sum(1 for v in EVENT_CATEGORY_MAP.values() if v == EventCategory.DECISION)
        assert count == 15  # 12 original + 3 canary/shadow events

    def test_action_events_count(self):
        count = sum(1 for v in EVENT_CATEGORY_MAP.values() if v == EventCategory.ACTION)
        assert count == 12

    def test_approval_events_count(self):
        count = sum(1 for v in EVENT_CATEGORY_MAP.values() if v == EventCategory.APPROVAL)
        assert count == 8

    def test_security_events_count(self):
        count = sum(1 for v in EVENT_CATEGORY_MAP.values() if v == EventCategory.SECURITY)
        assert count == 7

    def test_system_events_count(self):
        count = sum(1 for v in EVENT_CATEGORY_MAP.values() if v == EventCategory.SYSTEM)
        assert count == 8
