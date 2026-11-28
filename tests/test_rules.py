import pytest
import yaml

from blink_visual.detect.csp import diff_csp, parse_csp, script_policy, weaknesses
from blink_visual.errors import ConfigError
from blink_visual.findings import Finding, Severity
from blink_visual.rules import UNMATCHED_RULE, RuleEngine, default_rules, load_rules, parse_rules

# Every (detector, change_type) a detector can emit. A new change type must get a rule.
CHANGE_TYPES = {
    "scripts": ["added", "inline_added", "hash_changed", "sri_missing", "sri_mismatch", "removed"],
    "network": ["new_destination", "destination_removed"],
    "headers": [
        "csp_removed",
        "csp_weakened",
        "csp_weakness",
        "csp_changed",
        "csp_missing",
        "header_removed",
        "header_added",
        "header_changed",
        "header_missing",
    ],
    "forms": [
        "action_changed",
        "action_path_changed",
        "method_changed",
        "form_added",
        "form_removed",
        "input_added",
        "iframe_added",
        "iframe_removed",
    ],
    "dom": ["region_changed", "region_missing"],
    "visual": ["region_changed"],
    "tls": ["issuer_changed", "certificate_changed", "untrusted", "expiring", "tls_error"],
    "blink": ["detector_failed"],
}


def finding(detector, change_type, **attributes):
    return Finding(detector, change_type, "subject", "title", attributes=attributes)


@pytest.mark.parametrize(
    ("detector", "change_type"),
    [(d, c) for d, types in CHANGE_TYPES.items() for c in types],
)
def test_every_change_type_has_a_default_rule(detector, change_type):
    graded = RuleEngine().grade(finding(detector, change_type))
    assert graded.rule_id != UNMATCHED_RULE
    assert graded.why


def test_default_rule_ids_are_unique():
    ids = [r.id for r in default_rules().rules]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize(
    ("f", "severity"),
    [
        (finding("scripts", "added", cross_origin=True), Severity.HIGH),
        (finding("scripts", "added", cross_origin=False), Severity.MEDIUM),
        (finding("forms", "action_changed", cross_origin=True), Severity.CRITICAL),
        (
            finding("forms", "form_added", card_like=True, overlaps_payment_region=True),
            Severity.CRITICAL,
        ),
        (
            finding("forms", "form_added", card_like=True, overlaps_payment_region=False),
            Severity.HIGH,
        ),
        (finding("visual", "region_changed", changed_percentage=2.0), Severity.HIGH),
        (finding("visual", "region_changed", changed_percentage=1.99), Severity.MEDIUM),
        (
            finding("headers", "header_removed", header="x-frame-options", covered_by_csp=True),
            Severity.LOW,
        ),
        (
            finding("headers", "header_removed", header="x-frame-options", covered_by_csp=False),
            Severity.MEDIUM,
        ),
        (finding("network", "new_destination", sends_data=True, websocket=False), Severity.HIGH),
        (finding("network", "new_destination", sends_data=False, websocket=False), Severity.MEDIUM),
    ],
)
def test_default_severities(f, severity):
    assert RuleEngine().grade(f).severity is severity


def test_unmatched_findings_are_medium():
    graded = RuleEngine().grade(finding("future", "thing"))
    assert graded.severity is Severity.MEDIUM
    assert graded.rule_id == UNMATCHED_RULE


def test_project_rules_override_defaults(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": "acme.trusted-cdn",
                        "detector": "scripts",
                        "change_type": "added",
                        "when": {"cross_origin": True, "has_sri": {"eq": True}},
                        "severity": "low",
                        "why": "Our CDN scripts always carry SRI.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    engine = RuleEngine.for_file(path)
    assert (
        engine.grade(finding("scripts", "added", cross_origin=True, has_sri=True)).severity
        is Severity.LOW
    )
    assert (
        engine.grade(finding("scripts", "added", cross_origin=True, has_sri=False)).severity
        is Severity.HIGH
    )


@pytest.mark.parametrize(
    ("condition", "value", "matches"),
    [
        ({"gt": 1}, 2, True),
        ({"lt": 1}, 2, False),
        ({"lte": 2}, 2, True),
        ({"ne": "a"}, "b", True),
        ({"in": ["a", "b"]}, "a", True),
        ({"not_in": ["a"]}, "a", False),
        ({"exists": True}, None, True),
        ({"gte": 1}, "text", False),
    ],
)
def test_condition_operators(condition, value, matches):
    rules = parse_rules(
        {
            "rules": [
                {
                    "id": "r",
                    "detector": "*",
                    "when": {"x": condition},
                    "severity": "low",
                    "why": "w",
                }
            ]
        },
        source="test",
    )
    engine = RuleEngine(rules.rules)
    assert (engine.grade(finding("d", "c", x=value)).rule_id == "r") is matches


def test_exists_false_and_missing_attributes():
    rules = parse_rules(
        {
            "rules": [
                {
                    "id": "r",
                    "detector": "d",
                    "when": {"x": {"exists": False}},
                    "severity": "low",
                    "why": "w",
                }
            ]
        },
        source="test",
    )
    engine = RuleEngine(rules.rules)
    assert engine.grade(finding("d", "c")).rule_id == "r"
    assert engine.grade(finding("d", "c", x=1)).rule_id != "r"


@pytest.mark.parametrize(
    ("data", "fragment"),
    [
        ({"rules": [{"id": "r", "detector": "d", "severity": "urgent", "why": "w"}]}, "severity"),
        (
            {
                "rules": [
                    {
                        "id": "r",
                        "detector": "d",
                        "severity": "low",
                        "why": "w",
                        "when": {"x": {"regex": "a"}},
                    }
                ]
            },
            "unknown operator",
        ),
        ({"rules": [{"id": "R!", "detector": "d", "severity": "low", "why": "w"}]}, "id"),
        ({"version": 3}, "version"),
    ],
)
def test_invalid_rules(data, fragment):
    with pytest.raises(ConfigError, match=fragment):
        parse_rules(data, source="rules.yaml")


def test_load_rules_errors(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_rules(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules: [", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_rules(bad)


def test_severity_parsing():
    assert Severity.parse(" High ") is Severity.HIGH
    with pytest.raises(ValueError, match="expected one of"):
        Severity.parse("urgent")


# --- CSP -----------------------------------------------------------------------------


def test_parse_csp_normalizes_keywords_and_nonces():
    directives = parse_csp(
        "Script-Src 'SELF' 'nonce-r4nd0m' https://CDN.example 'sha256-AbC='; object-src 'none'"
    )
    assert directives["script-src"] == (
        "'self'",
        "'nonce-*'",
        "https://cdn.example",
        "'sha256-AbC='",
    )
    assert parse_csp("script-src 'nonce-a'") == parse_csp("script-src 'nonce-b'")


def test_multiple_policies_first_definition_wins():
    directives = parse_csp("script-src 'self', script-src 'none'\nimg-src *")
    assert directives["script-src"] == ("'self'",)
    assert directives["img-src"] == ("*",)


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ("script-src 'self'", set()),
        ("default-src 'self' 'unsafe-inline'", {"unsafe-inline"}),
        ("script-src 'unsafe-eval' https:", {"unsafe-eval", "wildcard-source"}),
        ("img-src 'self'", {"no-script-policy"}),
        ("script-src *", {"wildcard-source"}),
    ],
)
def test_csp_weaknesses(policy, expected):
    assert weaknesses(parse_csp(policy)) == expected


def test_script_policy_and_diff():
    old = parse_csp("default-src 'self'; script-src 'self' a.example")
    new = parse_csp("default-src 'self'; script-src 'self' b.example; img-src 'self'")
    assert script_policy(new) == ("'self'", "b.example")
    diff = diff_csp(old, new)
    assert diff.sources_added == {"script-src": ("b.example",)}
    assert diff.sources_removed == {"script-src": ("a.example",)}
    assert diff.directives_added == ("img-src",)
    assert not diff.empty
    assert diff_csp(old, old).empty
