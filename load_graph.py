"""
load_graph.py
=============
Builds a synthetic enterprise attack-graph in Neo4j so the agent has something
to reason over. This is a self-contained, deterministic version of the graph
described in the C3iHub internship work: hosts, network segments, applications,
identities, and CVEs, wired together with reachability and vulnerability edges.

Run this ONCE after starting Neo4j:

    python scripts/load_graph.py

It is idempotent: every node/edge is written with MERGE on a stable key, so
re-running never creates duplicates. If you already have your own graph loaded
from the internship, you can skip this script -- the agent only depends on the
node labels and relationship types documented in README.md, not on this loader.
"""

import os
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

# ---------------------------------------------------------------------------
# Synthetic enterprise definition (small, human-readable slice of the real one)
# ---------------------------------------------------------------------------

HOSTS = [
    # name, segment, internet_facing
    ("web-01",      "DMZ",        True),
    ("web-02",      "DMZ",        True),
    ("app-01",      "AppTier",    False),
    ("app-02",      "AppTier",    False),
    ("db-01",       "DataTier",   False),
    ("pci-db-01",   "PCIZone",    False),
    ("jump-01",     "MgmtTier",   False),
    ("dc-01",       "Identity",   False),  # domain controller
    ("file-01",     "Corp",       False),
    ("workstation-01", "Corp",    False),
]

SEGMENTS = [
    # name, cidr
    ("DMZ",      "10.0.1.0/24"),
    ("AppTier",  "10.0.2.0/24"),
    ("DataTier", "10.0.3.0/24"),
    ("PCIZone",  "10.0.4.0/24"),
    ("MgmtTier", "10.0.5.0/24"),
    ("Identity", "10.0.6.0/24"),
    ("Corp",     "10.0.7.0/24"),
]

# Which segments can route to which (directed reachability through routers).
SEGMENT_ROUTES = [
    ("DMZ",      "AppTier"),
    ("AppTier",  "DataTier"),
    ("AppTier",  "Identity"),
    ("MgmtTier", "PCIZone"),   # PCI reachable ONLY from Mgmt -> the choke point
    ("Corp",     "MgmtTier"),
    ("Corp",     "Identity"),
    ("Identity", "DataTier"),
]

APPLICATIONS = [
    # name, host, port
    ("nginx",        "web-01", 443),
    ("nginx",        "web-02", 443),
    ("tomcat",       "app-01", 8080),
    ("log4j-svc",    "app-02", 8080),   # the vulnerable one
    ("postgres",     "db-01",  5432),
    ("postgres",     "pci-db-01", 5432),
    ("ssh",          "jump-01", 22),
    ("ldap",         "dc-01",  389),
]

IDENTITIES = [
    # name, type, on_host
    ("svc_web",     "service", "web-01"),
    ("svc_app",     "service", "app-01"),
    ("svc_log4j",   "service", "app-02"),
    ("admin_db",    "user",    "db-01"),
    ("domain_admin","user",    "dc-01"),
    ("helpdesk",    "user",    "workstation-01"),
]

CVES = [
    # cve_id, on_app, attack_type, epss
    ("CVE-2021-44228", "log4j-svc", "remote-code-execution", 1.00),  # Log4Shell
    ("CVE-2019-0708",  "ssh",       "remote-code-execution", 0.94),  # BlueKeep-style
    ("CVE-2020-1472",  "ldap",      "privilege-escalation",  0.97),  # Zerologon-style
    ("CVE-2021-34527", "tomcat",    "remote-code-execution", 0.88),  # PrintNightmare-style
    ("CVE-2018-1058",  "postgres",  "privilege-escalation",  0.42),
]


def clear_graph(tx):
    tx.run("MATCH (n) DETACH DELETE n")


def create_constraints(tx):
    # Uniqueness constraints double as fast lookups and guarantee idempotency.
    tx.run("CREATE CONSTRAINT host_name IF NOT EXISTS FOR (h:Host) REQUIRE h.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT seg_name IF NOT EXISTS FOR (s:Segment) REQUIRE s.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE")
    tx.run("CREATE CONSTRAINT ident_name IF NOT EXISTS FOR (i:Identity) REQUIRE i.name IS UNIQUE")


def load(tx):
    # Segments
    for name, cidr in SEGMENTS:
        tx.run("MERGE (s:Segment {name:$name}) SET s.cidr=$cidr", name=name, cidr=cidr)

    # Hosts + membership in a segment
    for name, seg, internet in HOSTS:
        tx.run(
            """
            MERGE (h:Host {name:$name})
              SET h.internet_facing=$internet
            WITH h
            MATCH (s:Segment {name:$seg})
            MERGE (h)-[:IN_SEGMENT]->(s)
            """,
            name=name, internet=internet, seg=seg,
        )

    # Segment-to-segment routing (network reachability)
    for src, dst in SEGMENT_ROUTES:
        tx.run(
            """
            MATCH (a:Segment {name:$src}), (b:Segment {name:$dst})
            MERGE (a)-[:ROUTES_TO]->(b)
            """,
            src=src, dst=dst,
        )

    # Applications listening on hosts
    for app, host, port in APPLICATIONS:
        tx.run(
            """
            MERGE (a:Application {name:$app, host:$host})
              SET a.port=$port
            WITH a
            MATCH (h:Host {name:$host})
            MERGE (h)-[:RUNS]->(a)
            """,
            app=app, host=host, port=port,
        )

    # Identities present on hosts
    for name, itype, host in IDENTITIES:
        tx.run(
            """
            MERGE (i:Identity {name:$name})
              SET i.type=$itype
            WITH i
            MATCH (h:Host {name:$host})
            MERGE (i)-[:PRESENT_ON]->(h)
            """,
            name=name, itype=itype, host=host,
        )

    # CVEs attached to applications
    for cve, app, atype, epss in CVES:
        tx.run(
            """
            MERGE (c:CVE {cve_id:$cve})
              SET c.attack_type=$atype, c.epss=$epss
            WITH c
            MATCH (a:Application {name:$app})
            MERGE (a)-[:HAS_VULN]->(c)
            """,
            cve=cve, app=app, atype=atype, epss=epss,
        )

    # Derived EXPLOITS_TO edges: an RCE vuln lets an attacker move from the
    # vulnerable host to every host in a segment its segment routes to.
    tx.run(
        """
        MATCH (vulnHost:Host)-[:RUNS]->(:Application)-[:HAS_VULN]->(c:CVE)
        MATCH (vulnHost)-[:IN_SEGMENT]->(sFrom:Segment)-[:ROUTES_TO]->(sTo:Segment)
        MATCH (target:Host)-[:IN_SEGMENT]->(sTo)
        MERGE (vulnHost)-[e:CAN_REACH]->(target)
          SET e.via_cve = c.cve_id
        """
    )


def summarize(tx):
    counts = {}
    for label in ["Host", "Segment", "Application", "Identity", "CVE"]:
        counts[label] = tx.run(f"MATCH (n:{label}) RETURN count(n) AS c").single()["c"]
    rels = tx.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
    counts["relationships"] = rels
    return counts


def main():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as session:
        session.execute_write(clear_graph)
        session.execute_write(create_constraints)
        session.execute_write(load)
        counts = session.execute_read(summarize)
    driver.close()

    print("Graph loaded. Node / relationship counts:")
    for k, v in counts.items():
        print(f"  {k:15s} {v}")


if __name__ == "__main__":
    main()
