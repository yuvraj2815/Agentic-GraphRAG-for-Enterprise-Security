# Attack-Graph Security Agent (GraphRAG)

An LLM agent that answers natural-language security questions by reasoning over a
Neo4j **attack-graph**. Ask *"can the web server reach the domain controller?"*
and the agent decides which graph queries to run, traverses the graph, and
answers in plain English — citing the exact hosts and CVEs it used. Every factual
claim is grounded in real graph data, never guessed.

This is a **GraphRAG** system: retrieval-augmented generation where the retrieval
source is a graph database queried through tools, rather than a vector store.

![Architecture](assets/architecture.svg)

## Why this exists

Attack-graphs model an enterprise as nodes (hosts, segments, applications,
identities, CVEs) and directed edges (network reachability, vulnerability
exploits). They answer the question *"if an attacker breaks in here, what can
they reach, and how?"* — but querying them normally requires writing Cypher. This
project puts a natural-language agent in front of the graph so an analyst can ask
questions in English and get grounded, cited answers.

## How it works

The agent runs a tool-calling loop:

1. The user asks a question.
2. The LLM is given the question plus a set of **tools** (graph queries). It
   decides which tool to call and with what arguments.
3. The tool runs against Neo4j and returns structured data.
4. The LLM reads the result and either calls another tool (e.g. find a path,
   *then* rank the CVEs on it) or writes the final answer.
5. A hard iteration cap prevents infinite loops.

The three tools:

| Tool | Answers questions like | Returns |
|------|------------------------|---------|
| `find_attack_paths(source, target)` | "How does an attacker get from A to B?" | ordered host paths + the CVE on each hop |
| `get_node_neighbors(node)` | "What's running on this host?" | segment, apps, CVEs, identities, one-hop reach |
| `rank_cves_by_epss(limit)` | "What should we patch first?" | CVEs sorted by exploitation probability |

## Quickstart

### 1. Prerequisites
- Python 3.9+
- A running Neo4j instance (Neo4j Desktop or `docker run -p7687:7687 -p7474:7474 -e NEO4J_AUTH=neo4j/password neo4j:5`)
- An Anthropic API key ([console.anthropic.com](https://console.anthropic.com))

### 2. Install
```bash
git clone https://github.com/yuvraj2815/Agentic-GraphRAG-for-Enterprise-Security

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
```

### 3. Configure
```bash
copy .env.example .env
# edit .env: add your ANTHROPIC_API_KEY and Neo4j password
```

### 4. Load the graph
```bash
python scripts/load_graph.py
```
This builds a small synthetic enterprise (10 hosts, 7 segments, 8 apps, 5 real
CVEs) with derived reachability edges. It's idempotent — safe to re-run.

### 5. Run
```bash
# Sanity-check the query layer directly (no LLM):
python src/graph_tools.py

# Ask a one-off question from the terminal:
python -m src.agent "Which vulnerability should we patch first?"

# Or launch the chat UI:
python app.py
```

## Example interaction

> **Q:** Can web-01 reach the domain controller? If so, by what path?
>
> **A:** Yes. web-01 can reach dc-01 in two hops: web-01 → app-02 (exploiting
> CVE-2021-44228, Log4Shell) → dc-01. The path crosses from the DMZ into the
> AppTier and then into the Identity segment. Because Log4Shell has an EPSS score
> of 1.00, this is the highest-priority path to sever.

## Project structure

```
graphrag-security-agent/
├── app.py                  # Gradio chat UI
├── scripts/
│   └── load_graph.py       # builds the synthetic attack-graph in Neo4j
├── src/
│   ├── graph_tools.py      # the query layer: 3 functions that hit Neo4j
│   ├── tool_schemas.py     # describes those functions to the LLM
│   └── agent.py            # the tool-calling agent loop (the core)
├── tests/
│   └── test_graph_tools.py # tests the query layer against a live graph
├── assets/
│   └── architecture.svg
├── requirements.txt
├── .env.example
└── README.md
```

## Design decisions worth noting

- **The query layer knows nothing about the LLM.** `graph_tools.py` is pure
  database code you can test in isolation. This separation means a bug is either
  in the graph queries *or* the agent loop, never a tangle of both.
- **Errors become tool results, not crashes.** When a tool throws, the loop
  returns `is_error: True` to the model, which can then recover or explain the
  failure — the standard robust pattern for tool use.
- **Neighborhoods are capped.** `get_node_neighbors` limits its reachable-host
  list so a hub node can't flood the context window. This is deliberate context
  management, a core concern in agent design.
- **Grounding is enforced by the system prompt.** The model is instructed to cite
  exact host names and CVEs from tool output and to say "not reachable" rather
  than invent a path when a query comes back empty.

## Running the tests
```bash
pytest -q
```
Tests run against a loaded Neo4j and are skipped (not failed) if the database
isn't up, so `pytest` stays green anywhere.

## License
MIT — see [LICENSE](LICENSE).
