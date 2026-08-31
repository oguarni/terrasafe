"""Parser-shape contract: what the scanner may assume about parsed HCL.

Everything downstream of :class:`HCLParser` — resource lookup, structural
feature extraction, the rule engine, the risk score — reads the parse tree
positionally, by key. That shape is a moving target: ``python-hcl2`` v8 returns
block labels and string values *still wrapped in their literal quotes*, injects
``__is_block__`` into every block body and ``__comments__`` alongside them.

Under that shape ``resource["aws_security_group"]`` simply misses. Nothing
raises. Every structural feature reads zero and the risk score for a knowingly
vulnerable file falls from >=70 to 52 — a security scanner quietly
under-reporting risk, which is the worst failure mode this project has.

So these tests assert the *contract the scanner depends on*, not whichever
representation the current vendor version happens to emit. They must keep
passing across a parser upgrade; if one fails, the parse tree changed shape and
the consumers need a normalization boundary, not a relaxed assertion.
"""
import pytest

from terravault.application.feature_extraction import (
    FEATURE_NAMES,
    StructuralFeatureExtractor,
)
from terravault.application.scanner import IntelligentSecurityScanner
from terravault.domain.security_rules import SecurityRuleEngine
from terravault.infrastructure.ml_model import MLPredictor
from terravault.infrastructure.parser import HCLParser


pytestmark = pytest.mark.unit


# Exercises every construct the scanner actually inspects: block labels, nested
# blocks, string/bool/number scalars, a string list, and an interpolation.
CONTRACT_TF = """
variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  identifier          = "prod-db"
  storage_encrypted   = false
  publicly_accessible = true
  allocated_storage   = 20
  password            = var.db_password
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  encrypted         = true
  size              = 8
}

resource "aws_iam_role" "app" {
  name = "app-role"
}

resource "aws_iam_policy" "app" {
  name = "app-policy"
}

resource "aws_cloudtrail" "audit" {
  name = "audit-trail"
}

resource "aws_cloudwatch_log_group" "app" {
  name = "app-logs"
}
"""


@pytest.fixture
def parsed(tmp_path):
    """Parse through the production path, not ``hcl2`` directly.

    Going through :class:`HCLParser` is the point: it is the single seam where a
    normalization boundary can live, so the contract must be asserted on what it
    returns rather than on the raw loader output.
    """
    tf_file = tmp_path / "contract.tf"
    tf_file.write_text(CONTRACT_TF, encoding="utf-8")
    tf_content, raw_content = HCLParser().parse(str(tf_file))
    return tf_content, raw_content


def _walk(node):
    """Yield every mapping key and every string scalar in the tree."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield "key", key
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)
    elif isinstance(node, str):
        yield "value", node


# ---------------------------------------------------------------------------
# Shape invariants
# ---------------------------------------------------------------------------

def test_block_labels_are_unquoted(parsed):
    """``resource["aws_db_instance"]`` must match — not ``'"aws_db_instance"'``."""
    tf_content, _ = parsed
    types = {rtype for block in tf_content["resource"] for rtype in block}
    assert "aws_db_instance" in types
    assert "aws_security_group" in types
    assert not [t for t in types if t.startswith('"')], (
        f"block labels retain literal quotes: {sorted(types)}"
    )


def test_resource_names_are_unquoted(parsed):
    tf_content, _ = parsed
    names = {
        name
        for block in tf_content["resource"]
        for body in block.values()
        for name in (body if isinstance(body, dict) else {})
    }
    assert not [n for n in names if n.startswith('"')], (
        f"resource names retain literal quotes: {sorted(names)}"
    )


def test_string_values_are_unquoted(parsed):
    """A value of ``"tcp"`` must be ``tcp``, not ``'"tcp"'``.

    Quoted values break every literal comparison in the rule engine, including
    the ``0.0.0.0/0`` CIDR match that drives the open-ingress findings.
    """
    tf_content, _ = parsed
    quoted = [
        text
        for kind, text in _walk(tf_content)
        if kind == "value" and text.startswith('"') and text.endswith('"')
    ]
    assert not quoted, f"string values retain literal quotes: {quoted}"


def test_no_parser_metadata_keys_leak_into_the_tree(parsed):
    """``__is_block__`` / ``__comments__`` must not reach the consumers.

    Feature extraction iterates *every* key of a resource block as a resource
    type, so injected metadata keys are counted as if they were infrastructure.
    """
    tf_content, _ = parsed
    leaked = sorted({
        key
        for kind, key in _walk(tf_content)
        if kind == "key" and key.startswith("__") and key.endswith("__")
    })
    assert not leaked, f"parser metadata leaked into the parse tree: {leaked}"


def test_scalars_keep_their_native_types(parsed):
    """Booleans and numbers must not arrive as strings."""
    tf_content, _ = parsed
    db = _resource_body(tf_content, "aws_db_instance", "main")
    assert db["storage_encrypted"] is False
    assert db["publicly_accessible"] is True
    assert db["allocated_storage"] == 20

    ebs = _resource_body(tf_content, "aws_ebs_volume", "data")
    assert ebs["encrypted"] is True
    assert ebs["size"] == 8


def test_interpolations_are_preserved(parsed):
    """``var.x`` must stay recognisable so parametrized secrets are not flagged."""
    tf_content, _ = parsed
    db = _resource_body(tf_content, "aws_db_instance", "main")
    assert "${var.db_password}" == db["password"]


def test_nested_blocks_are_reachable_and_carry_their_lists(parsed):
    tf_content, _ = parsed
    sg = _resource_body(tf_content, "aws_security_group", "web")
    ingress = sg["ingress"]
    ingress = ingress[0] if isinstance(ingress, list) else ingress
    assert ingress["from_port"] == 22
    assert ingress["protocol"] == "tcp"
    assert ingress["cidr_blocks"] == ["0.0.0.0/0"]


def _resource_body(tf_content, rtype, name):
    """Look a resource body up the way the production consumers do."""
    for block in tf_content.get("resource", []):
        if rtype not in block:
            continue
        named = block[rtype]
        named = named[0] if isinstance(named, list) else named
        if name in named:
            body = named[name]
            return body[0] if isinstance(body, list) else body
    raise AssertionError(f"resource {rtype}.{name} not found in parse tree")


# ---------------------------------------------------------------------------
# Structural features — the values that silently went to zero
# ---------------------------------------------------------------------------

def test_structural_features_survive_the_parse(parsed):
    """Pin the exact features that read zero under an unnormalized parse tree.

    Each of these was observed collapsing under python-hcl2 v8: iam 2 -> 0,
    logging 2 -> 0, ingress 1 -> 0, encryption_coverage 0.5 -> 1.0. A zeroed
    feature vector means the ML side sees a benign-looking configuration.
    """
    tf_content, raw_content = parsed
    vector = StructuralFeatureExtractor().extract(tf_content, raw_content)
    features = dict(zip(FEATURE_NAMES, vector[0]))

    assert features["iam_resource_count"] == 2
    assert features["logging_resource_count"] == 2
    assert features["ingress_rule_count"] == 1
    assert features["encryption_coverage"] == pytest.approx(0.5)
    assert features["resource_count"] == 7
    assert features["public_exposure_count"] >= 1


def test_rule_engine_still_sees_the_planted_vulnerabilities(parsed):
    """The engine must find what was deliberately planted in the fixture.

    Asserted as a floor per rule rather than an exact total, so adding a new
    detection does not fail the test — but losing one does.
    """
    tf_content, raw_content = parsed
    findings = SecurityRuleEngine().analyze(tf_content, raw_content)
    messages = " ".join(f.message for f in findings)

    assert findings, "rule engine found nothing in a knowingly vulnerable fixture"
    assert "SSH" in messages or "0.0.0.0/0" in messages or "ingress" in messages.lower()
    assert any("ncrypt" in f.message for f in findings), (
        f"unencrypted aws_db_instance not reported: {messages}"
    )


# ---------------------------------------------------------------------------
# End-to-end risk score — the number that silently dropped to 52
# ---------------------------------------------------------------------------

def test_vulnerable_fixture_keeps_its_high_risk_score(tmp_path, vulnerable_tf):
    """The committed vulnerable fixture must still score >= 70.

    ``test_api.py`` asserts this through the API; this asserts it at the scanner
    so the floor is protected even when the HTTP layer is not in play. Under
    python-hcl2 v8 without normalization this returns 52 — no error, no warning,
    just a high-risk configuration reported as medium.
    """
    tf_file = tmp_path / "vulnerable.tf"
    tf_file.write_bytes(vulnerable_tf)

    scanner = IntelligentSecurityScanner(
        parser=HCLParser(),
        rule_analyzer=SecurityRuleEngine(),
        ml_predictor=MLPredictor(),
    )
    result = scanner.scan(str(tf_file))

    assert result["score"] >= 70, (
        f"risk score regressed to {result['score']} for the vulnerable fixture; "
        "a parse-shape change can cause this silently"
    )
    assert result["vulnerabilities"], "no vulnerabilities reported for the vulnerable fixture"
