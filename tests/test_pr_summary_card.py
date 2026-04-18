# tests/test_pr_summary_card.py
from vigilant.communication.reviewer import Reviewer
from vigilant.models import PRIntent, Vulnerability, VulnerabilityStatus, TaintPath, TaintNode

def test_generate_pr_summary_card_high_risk():
    node = TaintNode(node_id="1", file_path="test.py", function_name="memcpy", line_number=1, node_role="SINK", label="memcpy")
    path = TaintPath(path_id="1", source=node, sink=node)
    v = Vulnerability(vuln_id="1", taint_path=path, status=VulnerabilityStatus.SANDBOX_VERIFIED, confidence=1.0)
    intent = PRIntent(purpose="Test PR")
    
    card = Reviewer._generate_pr_summary_card(intent, [v], ["test.py"])
    assert "**Risk level** | 🔴 HIGH" in card
    assert "**Verified bugs** | 1" in card
    assert "**Files reviewed** | 1" in card

def test_generate_pr_summary_card_low_risk():
    intent = PRIntent(purpose="Clean PR")
    card = Reviewer._generate_pr_summary_card(intent, [], ["test.py"])
    assert "**Risk level** | ✅ LOW" in card
    assert "**Verified bugs** | 0" in card
    assert "**Files reviewed** | 1" in card
