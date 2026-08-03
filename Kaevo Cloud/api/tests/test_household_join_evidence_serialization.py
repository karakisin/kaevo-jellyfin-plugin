import json
from decimal import Decimal

from household_join_evidence import render_evidence


def test_dynamodb_decimal_values_render_for_local_evidence_without_mutating_the_record():
    stored = {
        "attempts": Decimal("3"),
        "expires_at": Decimal("1785000000"),
        "nested": {"ratio": Decimal("0.125")},
    }

    rendered = json.loads(render_evidence(stored))

    assert rendered == {"attempts": 3, "expires_at": 1785000000, "nested": {"ratio": "0.125"}}
    assert stored["attempts"] == Decimal("3")
    assert stored["expires_at"] == Decimal("1785000000")
    assert stored["nested"]["ratio"] == Decimal("0.125")
    assert isinstance(stored["nested"]["ratio"], Decimal)
