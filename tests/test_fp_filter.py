# tests/test_fp_filter.py
from pathlib import Path
from vigilant.models import Vulnerability, VulnerabilityStatus, TaintPath, TaintNode
from vigilant.fp_filter import apply_fp_filter

def test_apply_fp_filter_drops_safe_sink():
    # Setup a vuln with a safe sink (from fp_safe_patterns.yaml)
    node = TaintNode(node_id="1", file_path="test.py", function_name="logging.getLogger", line_number=1, node_role="SINK", label="logging.getLogger")
    path = TaintPath(path_id="1", source=node, sink=node)
    v = Vulnerability(vuln_id="1", taint_path=path, status=VulnerabilityStatus.PROVEN, confidence=0.9)
    
    kept, dropped = apply_fp_filter([v])
    assert len(kept) == 0
    assert len(dropped) == 1
    assert dropped[0].vuln_id == "1"

def test_apply_fp_filter_demotes_safe_intermediate():
    # Setup a vuln with a safe intermediate
    src = TaintNode(node_id="1", file_path="test.py", function_name="argv", line_number=1, node_role="SOURCE", label="argv")
    # Use a non-high-confidence sink so demotion happens
    snk = TaintNode(node_id="2", file_path="test.py", function_name="custom_sink", line_number=10, node_role="SINK", label="custom_sink")
    inter = TaintNode(node_id="3", file_path="test.py", function_name="std::vector::push_back", line_number=5, node_role="INTERMEDIATE", label="std::vector::push_back")
    path = TaintPath(path_id="1", source=src, sink=snk, intermediate_nodes=[inter])
    v = Vulnerability(vuln_id="1", taint_path=path, status=VulnerabilityStatus.PROVEN, confidence=0.95)
    
    kept, dropped = apply_fp_filter([v])
    assert len(kept) == 1
    assert len(dropped) == 0
    assert kept[0].status == VulnerabilityStatus.LIKELY
    assert kept[0].confidence == 0.72

def test_apply_fp_filter_drops_self_loop():
    node = TaintNode(node_id="1", file_path="test.py", function_name="memcpy", line_number=1, node_role="SINK", label="memcpy")
    path = TaintPath(path_id="1", source=node, sink=node)
    v = Vulnerability(vuln_id="1", taint_path=path, status=VulnerabilityStatus.PROVEN, confidence=0.9)
    
    kept, dropped = apply_fp_filter([v])
    assert len(kept) == 0
    assert len(dropped) == 1
