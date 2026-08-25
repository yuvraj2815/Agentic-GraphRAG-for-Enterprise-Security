"""
tool_schemas.py
===============
The bridge between your Python functions and the LLM. Each entry describes ONE
tool in the format the Anthropic Messages API expects:

    {
        "name":        matches the Python function name,
        "description": how the model decides WHEN to use it (be specific!),
        "input_schema": JSON Schema for the arguments the model must supply,
    }

The `description` field is the single most important thing in this file. A vague
description is the #1 cause of an agent calling the wrong tool or inventing bad
arguments. Each one below states exactly what the tool does, what it returns, and
when to reach for it.

TOOL_REGISTRY maps each tool name to the actual Python callable, so the agent
loop can dispatch a tool_use block to real code with one dict lookup.
"""

from . import graph_tools

TOOLS = [
    {
        "name": "find_attack_paths",
        "description": (
            "Find attack paths from a SOURCE host to a TARGET host in the "
            "enterprise attack-graph. Use this whenever the user asks whether "
            "or how an attacker could get from one machine to another, e.g. "
            "'can the web server reach the domain controller?' or 'what path "
            "leads to the PCI database?'. Returns an ordered list of hosts for "
            "each path and the CVE exploited on each hop. Returns an empty list "
            "if no path exists (which is itself a meaningful security answer: "
            "the target is not reachable from that source)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "description": "Name of the entry/source host, e.g. 'web-01'.",
                },
                "target": {
                    "type": "string",
                    "description": "Name of the goal/target host, e.g. 'dc-01'.",
                },
            },
            "required": ["source", "target"],
        },
    },
    {
        "name": "get_node_neighbors",
        "description": (
            "Return everything directly attached to a single host: its network "
            "segment, the applications it runs, the CVEs on those applications, "
            "the identities present on it, and the hosts it can reach in one "
            "hop. Use this to inspect or describe one machine, or as a first "
            "step before tracing longer paths, e.g. 'what is running on app-02?' "
            "or 'what is exposed on the jump host?'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "node": {
                    "type": "string",
                    "description": "Name of the host to inspect, e.g. 'app-02'.",
                },
            },
            "required": ["node"],
        },
    },
    {
        "name": "rank_cves_by_epss",
        "description": (
            "List the CVEs present in the environment ordered by EPSS "
            "(Exploit Prediction Scoring System) score, highest first, with the "
            "host and application each sits on. EPSS estimates the probability a "
            "vulnerability will be exploited in the wild. Use this whenever the "
            "user asks what is most dangerous, most likely to be exploited, or "
            "what to patch first, e.g. 'what is the riskiest vulnerability?' or "
            "'prioritise the CVEs for me'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "How many CVEs to return (default 10).",
                },
            },
            "required": [],
        },
    },
]

# Dispatch table: tool name -> Python callable. The agent loop uses this to run
# whatever tool the model asks for.
TOOL_REGISTRY = {
    "find_attack_paths": graph_tools.find_attack_paths,
    "get_node_neighbors": graph_tools.get_node_neighbors,
    "rank_cves_by_epss": graph_tools.rank_cves_by_epss,
}
