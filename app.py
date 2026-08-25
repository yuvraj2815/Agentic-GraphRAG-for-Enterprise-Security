"""
app.py
======
A minimal chat UI over the agent, built with Gradio. Run:

    python app.py

then open the local URL it prints. Each browser session gets its own Agent
instance (its own conversation history) via gr.State.

The example questions in the sidebar are chosen to show range:
  - a one-hop inspection      (get_node_neighbors)
  - a multi-hop path          (find_attack_paths)
  - a prioritisation question (rank_cves_by_epss)
  - a "no path" question that proves the agent doesn't hallucinate reachability
"""

import gradio as gr
from src.agent import Agent

EXAMPLES = [
    "What is running on app-02, and is it vulnerable?",
    "Can web-01 reach the domain controller? If so, by what path?",
    "Which vulnerability should we patch first, and why?",
    "Is the PCI database reachable from the DMZ?",
]

INTRO = """# Attack-Graph Security Agent
Ask questions in plain English about an enterprise network. The agent queries a
Neo4j attack-graph with tools and answers **only** from what the graph returns —
every path and CVE it cites is real graph data, not a guess.
"""


def respond(message, history, agent_state):
    if agent_state is None:
        agent_state = Agent()
    answer = agent_state.ask(message)
    history = history + [(message, answer)]
    return history, agent_state, ""


def reset():
    return [], Agent(), ""


with gr.Blocks(title="Attack-Graph Security Agent", theme=gr.themes.Soft()) as demo:
    gr.Markdown(INTRO)
    agent_state = gr.State(None)

    chatbot = gr.Chatbot(height=460, label="Conversation")
    with gr.Row():
        msg = gr.Textbox(
            placeholder="e.g. Can web-01 reach the domain controller?",
            scale=8,
            show_label=False,
        )
        send = gr.Button("Ask", variant="primary", scale=1)
        clear = gr.Button("Reset", scale=1)

    gr.Examples(examples=EXAMPLES, inputs=msg, label="Try one of these")

    send.click(respond, [msg, chatbot, agent_state], [chatbot, agent_state, msg])
    msg.submit(respond, [msg, chatbot, agent_state], [chatbot, agent_state, msg])
    clear.click(reset, outputs=[chatbot, agent_state, msg])


if __name__ == "__main__":
    demo.launch()
