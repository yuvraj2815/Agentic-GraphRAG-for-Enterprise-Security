"""
agent.py
========
The agent loop -- the core of the project. This is what makes it "agentic"
rather than a single question-answer call: the model can call a tool, read the
result, decide it needs another tool, call that, and only then answer. The loop
below runs that cycle until the model stops asking for tools.

Flow (one call to `ask`):

    1. Send [conversation so far] + [tool schemas] to the model.
    2. Look at the response:
         - if it contains tool_use blocks -> run each tool, append the results
           as tool_result blocks, and go back to step 1.
         - if it is plain text -> that is the final answer. Stop.
    3. A hard iteration cap stops a confused model looping forever.

Every tool call is wrapped so that an exception becomes a tool_result with
is_error=True. The model reads that error and can recover (retry with different
arguments, or explain the failure to the user) instead of the whole program
crashing.
"""

import os
import json
import anthropic
from dotenv import load_dotenv

from .tool_schemas import TOOLS, TOOL_REGISTRY

load_dotenv()

MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
MAX_ITERATIONS = 6  # safety cap on tool-calling rounds per question

SYSTEM_PROMPT = """You are a security analyst assistant. You answer questions \
about an enterprise network by using the provided tools to query an attack-graph \
database. You never invent hosts, CVEs, paths, or scores -- every factual claim \
in your answer must come from a tool result.

Rules:
- Always ground your answer in tool output. If a tool returns no data, say so \
plainly rather than guessing.
- When you describe an attack path, cite the exact host names in order and the \
CVE used on each hop, exactly as returned by the tools.
- Prefer to answer in a few clear sentences. Use a short list only when \
enumerating multiple paths or CVEs.
- If a question needs several steps (e.g. find a path, then rank its CVEs), use \
the tools in sequence before answering.
"""


class Agent:
    """A stateful agent. Each instance keeps its own conversation history so a
    Gradio session (or a test) can hold a multi-turn conversation."""

    def __init__(self, model: str = MODEL, verbose: bool = False):
        self.client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
        self.model = model
        self.verbose = verbose
        self.messages = []  # running conversation (user/assistant turns)

    def _run_tool(self, name: str, args: dict) -> dict:
        """Execute one tool by name, converting any exception into an error
        payload the model can read."""
        if self.verbose:
            print(f"  -> tool call: {name}({args})")
        try:
            fn = TOOL_REGISTRY[name]
            result = fn(**args)
            return {"content": json.dumps(result), "is_error": False}
        except Exception as exc:  # noqa: BLE001 -- we deliberately catch all
            return {"content": f"Error running {name}: {exc}", "is_error": True}

    def ask(self, question: str) -> str:
        """Ask one question and return the final grounded answer as text.
        Tool-calling rounds happen internally and are invisible to the caller."""
        self.messages.append({"role": "user", "content": question})

        for _ in range(MAX_ITERATIONS):
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=self.messages,
            )

            # Record the assistant turn verbatim (may contain tool_use blocks).
            self.messages.append({"role": "assistant", "content": response.content})

            # Collect any tool_use blocks the model produced this round.
            tool_uses = [b for b in response.content if b.type == "tool_use"]

            if not tool_uses:
                # No tools requested -> the model has produced its final answer.
                text = "".join(b.text for b in response.content if b.type == "text")
                return text.strip()

            # Run every requested tool and feed the results back in one user turn.
            tool_results = []
            for block in tool_uses:
                outcome = self._run_tool(block.name, block.input)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": outcome["content"],
                        "is_error": outcome["is_error"],
                    }
                )
            self.messages.append({"role": "user", "content": tool_results})

        # If we fall out of the loop, the model kept asking for tools past the cap.
        return (
            "I wasn't able to reach a final answer within the tool-call limit. "
            "Try asking a more specific question."
        )


def ask_once(question: str, verbose: bool = False) -> str:
    """Convenience one-shot helper for scripts and quick tests."""
    return Agent(verbose=verbose).ask(question)


if __name__ == "__main__":
    import sys

    q = " ".join(sys.argv[1:]) or "What is the riskiest path from web-01 to the domain controller?"
    print(f"Q: {q}\n")
    print("A:", ask_once(q, verbose=True))
