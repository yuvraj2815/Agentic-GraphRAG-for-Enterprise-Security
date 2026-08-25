"""
graph_tools.py
==============
The query layer. These are plain Python functions that talk to Neo4j and return
clean, JSON-serializable dictionaries. They know NOTHING about the LLM -- that
separation is deliberate. You can test every function here by hand before any
agent code exists, which means when something breaks later you know it is the
agent loop, not the database.

Each public function maps 1:1 to a tool the agent can call:

    find_attack_paths(source, target)   -> paths between two hosts
    get_node_neighbors(node)            -> what a host connects to
    rank_cves_by_epss(limit)            -> most-exploitable CVEs first

Design notes
------------
* A single module-level driver is reused across calls (connection pooling is
  handled by the Neo4j driver itself -- one driver, many sessions).
* Every function opens a short-lived session and closes it via `with`.
* Errors are raised, not swallowed. The agent loop is responsible for turning
  an exception into a tool_result with is_error=True (see agent.py).
"""

import os
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

_NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
_NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

# One driver for the whole process. The driver maintains an internal connection
# pool, so this is the recommended pattern (do NOT open a driver per query).
_driver = GraphDatabase.driver(_NEO4J_URI, auth=(_NEO4J_USER, _NEO4J_PASSWORD))


def close():
    """Close the shared driver. Call once on shutdown."""
    _driver.close()


# ---------------------------------------------------------------------------
# Tool 1: attack-path discovery
# ---------------------------------------------------------------------------

def find_attack_paths(source: str, target: str, max_hops: int = 6) -> dict:
    """
    Find attack paths from `source` host to `target` host using the derived
    CAN_REACH edges. Returns up to a handful of shortest paths as ordered lists
    of host names, plus the CVE used on each hop.

    Parameters
    ----------
    source : str   Name of the entry host (e.g. "web-01").
    target : str   Name of the goal host (e.g. "dc-01").
    max_hops : int Cap on path length to keep queries bounded.

    Returns
    -------
    dict with keys:
        source, target, path_count, paths
    where each path is {"hosts": [...], "vias": [...]}.
    """
    query = """
    MATCH (s:Host {name:$source}), (t:Host {name:$target})
    MATCH p = (s)-[:CAN_REACH*1..%d]->(t)
    WITH p, relationships(p) AS rels, nodes(p) AS ns
    RETURN [n IN ns | n.name] AS hosts,
           [r IN rels | r.via_cve] AS vias
    ORDER BY length(p) ASC
    LIMIT 5
    """ % max_hops

    with _driver.session() as session:
        result = session.run(query, source=source, target=target)
        paths = [{"hosts": r["hosts"], "vias": r["vias"]} for r in result]

    return {
        "source": source,
        "target": target,
        "path_count": len(paths),
        "paths": paths,
    }


# ---------------------------------------------------------------------------
# Tool 2: neighborhood expansion
# ---------------------------------------------------------------------------

def get_node_neighbors(node: str, limit: int = 20) -> dict:
    """
    Return everything directly connected to a host: the segment it lives in,
    the applications it runs, the CVEs on those apps, the identities present,
    and the hosts it can reach in one hop.

    `limit` caps the reachable-host list so a hub node cannot flood the context
    window -- this is the pruning that keeps agent turns cheap.
    """
    with _driver.session() as session:
        segment = session.run(
            "MATCH (h:Host {name:$node})-[:IN_SEGMENT]->(s:Segment) RETURN s.name AS name, s.cidr AS cidr",
            node=node,
        ).single()

        apps = session.run(
            "MATCH (h:Host {name:$node})-[:RUNS]->(a:Application) RETURN a.name AS name, a.port AS port",
            node=node,
        ).data()

        cves = session.run(
            """
            MATCH (h:Host {name:$node})-[:RUNS]->(:Application)-[:HAS_VULN]->(c:CVE)
            RETURN c.cve_id AS cve_id, c.attack_type AS attack_type, c.epss AS epss
            ORDER BY c.epss DESC
            """,
            node=node,
        ).data()

        identities = session.run(
            "MATCH (i:Identity)-[:PRESENT_ON]->(h:Host {name:$node}) RETURN i.name AS name, i.type AS type",
            node=node,
        ).data()

        reachable = session.run(
            """
            MATCH (h:Host {name:$node})-[e:CAN_REACH]->(t:Host)
            RETURN t.name AS name, e.via_cve AS via_cve
            LIMIT $limit
            """,
            node=node, limit=limit,
        ).data()

    return {
        "node": node,
        "segment": dict(segment) if segment else None,
        "applications": apps,
        "vulnerabilities": cves,
        "identities": identities,
        "can_reach": reachable,
    }


# ---------------------------------------------------------------------------
# Tool 3: EPSS ranking
# ---------------------------------------------------------------------------

def rank_cves_by_epss(limit: int = 10) -> dict:
    """
    Return CVEs in the graph ordered by EPSS (exploitation-probability) score,
    highest first, with the host and application each one sits on. This is how
    the agent answers "what is most likely to be exploited?".
    """
    query = """
    MATCH (h:Host)-[:RUNS]->(a:Application)-[:HAS_VULN]->(c:CVE)
    RETURN c.cve_id AS cve_id, c.epss AS epss, c.attack_type AS attack_type,
           a.name AS application, h.name AS host, h.internet_facing AS internet_facing
    ORDER BY c.epss DESC
    LIMIT $limit
    """
    with _driver.session() as session:
        rows = session.run(query, limit=limit).data()

    return {"count": len(rows), "cves": rows}


# ---------------------------------------------------------------------------
# Manual test harness: run `python src/graph_tools.py` to sanity-check each
# function against your live Neo4j WITHOUT any LLM involved.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    print("== find_attack_paths(web-01 -> dc-01) ==")
    print(json.dumps(find_attack_paths("web-01", "dc-01"), indent=2))

    print("\n== get_node_neighbors(app-02) ==")
    print(json.dumps(get_node_neighbors("app-02"), indent=2))

    print("\n== rank_cves_by_epss(5) ==")
    print(json.dumps(rank_cves_by_epss(5), indent=2))

    close()
