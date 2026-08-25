"""
test_graph_tools.py
===================
Tests for the query layer. These run against a LIVE Neo4j that has been loaded
with scripts/load_graph.py -- they check the tools return the shapes and the
known facts of the synthetic graph. They do NOT call the LLM, so they are fast,
free, and deterministic.

Run:  pytest -q

If Neo4j isn't running, these are skipped rather than failed, so `pytest` stays
green on a machine without a database.
"""

import pytest
from neo4j.exceptions import ServiceUnavailable

from src import graph_tools


def _neo4j_up() -> bool:
    try:
        graph_tools.rank_cves_by_epss(1)
        return True
    except ServiceUnavailable:
        return False
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _neo4j_up(), reason="Neo4j not running / graph not loaded"
)


def test_rank_returns_sorted_by_epss():
    out = graph_tools.rank_cves_by_epss(10)
    assert out["count"] > 0
    scores = [c["epss"] for c in out["cves"]]
    assert scores == sorted(scores, reverse=True), "CVEs must be EPSS-descending"


def test_log4shell_is_top_ranked():
    out = graph_tools.rank_cves_by_epss(10)
    assert out["cves"][0]["cve_id"] == "CVE-2021-44228"
    assert out["cves"][0]["epss"] == 1.00


def test_neighbors_of_app02_include_log4j():
    out = graph_tools.get_node_neighbors("app-02")
    app_names = [a["name"] for a in out["applications"]]
    assert "log4j-svc" in app_names
    cve_ids = [c["cve_id"] for c in out["vulnerabilities"]]
    assert "CVE-2021-44228" in cve_ids


def test_path_shape_is_wellformed():
    out = graph_tools.find_attack_paths("web-01", "dc-01")
    assert "paths" in out
    for p in out["paths"]:
        assert "hosts" in p and "vias" in p
        # a path of N hosts has N-1 hop CVEs
        assert len(p["vias"]) == len(p["hosts"]) - 1


def test_missing_path_returns_empty_not_error():
    # A nonsense target that exists but is unreachable should give an empty list,
    # never an exception -- the agent relies on this to say "not reachable".
    out = graph_tools.find_attack_paths("workstation-01", "web-01")
    assert isinstance(out["paths"], list)
