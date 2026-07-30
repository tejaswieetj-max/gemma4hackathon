import json
import os
import gradio as gr
import requests

# Pointing to Member 3's single-call evaluation endpoint:
API_URL = "http://localhost:8000/api/v1/check"

# Safely locate and load test_suite.json
json_path = os.path.join(os.path.dirname(__file__), "test_suite.json")
try:
    with open(json_path, "r", encoding="utf-8") as f:
        test_suite = json.load(f)
except Exception:
    test_suite = []


def get_mock_response(text: str) -> dict:
    """Mock fallback so Member 4 can test UI immediately without Member 3's server."""
    text_lower = text.lower()
    is_malicious = any(
        kw in text_lower
        for kw in ["dan", "ignore", "disregard", "pick a lock", "maranthuko"]
    )
    is_tanglish = any(
        kw in text_lower for kw in ["maranthuko", "sollu", "mami", "nanba"]
    )

    return {
        "verdict": "MALICIOUS" if is_malicious else "CLEAN",
        "risk_score": 0.88 if is_malicious else 0.05,
        "perplexity_score": 45.2 if is_malicious else 11.3,
        "vector_drift": 0.72 if is_malicious else 0.02,
        "reasoning": (
            "Detected system prompt extraction or roleplay jailbreak attempt."
            if is_malicious
            else "Passed guardrail check cleanly."
        ),
        "detected_language": "Tanglish" if is_tanglish else "English",
        "attack_type": (
            "direct_injection" if is_malicious else "none"
        ),
    }


def check_prompt(text):
    if not text.strip():
        return ("NONE", 0.0, 0.0, 0.0, "Empty prompt provided.", "Unknown", "none")

    try:
        # Call Member 3's POST /api/v1/check endpoint
        response = requests.post(
            API_URL,
            json={"prompt": text},
            timeout=3.0,
        )
        if response.status_code == 200:
            final = response.json()
        else:
            final = get_mock_response(text)
    except Exception:
        # Fallback to local mock response if server isn't running
        final = get_mock_response(text)

    return (
        final.get("verdict", "UNKNOWN"),
        final.get("risk_score", 0.0),
        final.get("perplexity_score", 0.0),
        final.get("vector_drift", 0.0),
        final.get("reasoning", "N/A"),
        final.get("detected_language", "N/A"),
        final.get("attack_type", "none"),
    )


with gr.Blocks(title="Gemma Guard Firewall") as demo:
    gr.Markdown("## 🛡️ Multilingual Prompt Injection Firewall")

    inp = gr.Textbox(
        label="Input Prompt",
        lines=4,
        placeholder="Type a query or click a test button below...",
    )
    btn = gr.Button("Check Security", variant="primary")

    gr.Markdown("### 🧪 Benchmark Test Presets")
    # Replace your current loop with this:
    with gr.Row():
        for case in test_suite[:6]:
            btn_label = f"{case.get('id', 'Test')} ({case.get('language', 'En')})"
            btn = gr.Button(btn_label)
            # Using case=case in the click handler binds the prompt correctly per button
            btn.click(
                fn=lambda prompt=case.get("prompt", ""): prompt,
                outputs=inp
            )

    verdict = gr.Label(label="Verdict")
    with gr.Row():
        risk = gr.Number(label="Risk Score")
        perp = gr.Number(label="Perplexity")
        drift = gr.Number(label="Vector Drift")

    reasoning = gr.Textbox(label="Reasoning")
    lang = gr.Textbox(label="Detected Language")
    attack = gr.Textbox(label="Attack Type")

    btn.click(
        check_prompt,
        inputs=inp,
        outputs=[verdict, risk, perp, drift, reasoning, lang, attack],
    )

if __name__ == "__main__":
    demo.launch()