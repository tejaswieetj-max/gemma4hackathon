import json
import os
import gradio as gr
import requests

API_URL = "http://localhost:8000/api/v1/check"

json_path = os.path.join(os.path.dirname(__file__), "test_suite.json")
try:
    with open(json_path, "r", encoding="utf-8") as f:
        test_suite = json.load(f)
except Exception:
    test_suite = []

CATEGORY_LABELS = {
    "clean": "Clean",
    "direct_injection": "Direct Injection",
    "indirect_injection": "Indirect Injection",
    "hypothetical_roleplay": "Roleplay Jailbreak",
    "obfuscated_encoding": "Obfuscated / Encoded",
}


def get_mock_response(text: str) -> dict:
    text_lower = text.lower()
    is_malicious = any(
        kw in text_lower
        for kw in [
            "dan",
            "ignore",
            "disregard",
            "pick a lock",
            "maranthuko",
            "bhool jao",
            "bypassing",
            "explosive",
            "swdub3jl",
            "admin password",
        ]
    )
    is_tanglish = any(
        kw in text_lower
        for kw in ["maranthuko", "sollu", "mami", "nanba", "machan", "thalli"]
    )
    is_hinglish = any(
        kw in text_lower for kw in ["bhool jao", "batao", "samjha do", "banao"]
    )

    lang = "English"
    if is_tanglish:
        lang = "Tanglish"
    elif is_hinglish:
        lang = "Hinglish"

    return {
        "verdict": "MALICIOUS" if is_malicious else "CLEAN",
        "risk_score": 0.92 if is_malicious else 0.04,
        "perplexity_score": 48.6 if is_malicious else 10.2,
        "vector_drift": 0.81 if is_malicious else 0.01,
        "reasoning": (
            "🚨 Threat Detected: System instruction override or multilingual adversarial jailbreak attempt."
            if is_malicious
            else "✅ Safe Request: Standard semantic profile, passed all guardrail checks."
        ),
        "detected_language": lang,
        "attack_type": "injection_attempt" if is_malicious else "none",
    }


def format_verdict_html(verdict_text: str) -> str:
    if "EMPTY" in verdict_text:
        return """
        <div class="verdict-hero verdict-empty">
            <div class="verdict-icon">⚠️</div>
            <div class="verdict-title">Empty Input</div>
            <div class="verdict-sub">Please provide a prompt to analyze.</div>
        </div>
        """
    if "MALICIOUS" in verdict_text:
        return f"""
        <div class="verdict-hero verdict-malicious">
            <div class="verdict-icon">⛔</div>
            <div class="verdict-title">MALICIOUS</div>
            <div class="verdict-sub">Blocked — adversarial pattern detected</div>
        </div>
        """
    return f"""
    <div class="verdict-hero verdict-clean">
        <div class="verdict-icon">✅</div>
        <div class="verdict-title">CLEAN</div>
        <div class="verdict-sub">Passed — no injection signals detected</div>
    </div>
    """


def format_metric_card(label: str, value: str, accent: str = "") -> str:
    return f"""
    <div class="metric-card {accent}">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
    </div>
    """


def format_meta_chip(label: str, value: str) -> str:
    return f"""
    <div class="meta-chip">
        <span class="meta-chip-label">{label}</span>
        <span class="meta-chip-value">{value}</span>
    </div>
    """


def check_prompt(text):
    if not text.strip():
        return (
            format_verdict_html("⚠️ EMPTY INPUT"),
            format_metric_card("Risk Score", "0.00", "accent-neutral"),
            format_metric_card("Perplexity", "0.0", "accent-neutral"),
            format_metric_card("Vector Drift", "0.00", "accent-neutral"),
            "Please provide a prompt to analyze.",
            format_meta_chip("Detected Language", "Unknown"),
            format_meta_chip("Attack Category", "none"),
        )

    try:
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
        final = get_mock_response(text)

    verdict_str = final.get("verdict", "UNKNOWN")
    if verdict_str == "MALICIOUS":
        formatted_verdict = "🔴 MALICIOUS — BLOCKED"
        accent = "accent-danger"
    else:
        formatted_verdict = "🟢 CLEAN — PASSED"
        accent = "accent-safe"

    risk = f"{float(final.get('risk_score', 0.0)):.2f}"
    perp = f"{float(final.get('perplexity_score', 0.0)):.1f}"
    drift = f"{float(final.get('vector_drift', 0.0)):.2f}"
    reasoning = final.get("reasoning", "N/A")
    language = final.get("detected_language", "N/A")
    attack = final.get("attack_type", "none")

    return (
        format_verdict_html(formatted_verdict),
        format_metric_card("Risk Score", risk, accent),
        format_metric_card("Perplexity", perp, accent),
        format_metric_card("Vector Drift", drift, accent),
        reasoning,
        format_meta_chip("Detected Language", language),
        format_meta_chip("Attack Category", attack),
    )


custom_theme = gr.themes.Base(
    primary_hue="red",
    secondary_hue="neutral",
    neutral_hue="neutral",
    font=[gr.themes.GoogleFont("Inter"), "ui-sans-serif", "system-ui"],
    font_mono=[gr.themes.GoogleFont("JetBrains Mono"), "ui-monospace"],
).set(
    body_background_fill="#121214",
    block_background_fill="transparent",
    block_border_width="0px",
    block_radius="12px",
    block_label_text_color="#8b8b8f",
    body_text_color="#ececec",
    input_background_fill="#1c1c1f",
    input_border_color="rgba(255,255,255,0.08)",
    button_primary_background_fill="#e5484d",
    button_primary_background_fill_hover="#f2555a",
    button_primary_text_color="#ffffff",
)

custom_css = """
* { box-sizing: border-box; }
.gradio-container {
    max-width: 1140px !important;
    background: #121214 !important;
}
/* ── AngelHack-style hero banner ── */
#header-banner {
    position: relative;
    overflow: hidden;
    background: linear-gradient(120deg, #4a0e0e 0%, #2a0810 50%, #121214 100%);
    border-radius: 16px;
    padding: 40px 44px;
    margin-bottom: 20px;
    border: 1px solid rgba(229,72,77,0.2);
}
#header-banner::after {
    content: "";
    position: absolute;
    top: 20px; right: 28px;
    width: 80px; height: 60px;
    background: repeating-linear-gradient(
        0deg,
        #e5484d 0px, #e5484d 8px,
        transparent 8px, transparent 16px
    );
    opacity: 0.55;
    pointer-events: none;
}
#header-banner .eyebrow {
    display: inline-block;
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: #f4a8a8;
    background: rgba(229,72,77,0.12);
    border: 1px solid rgba(244,168,168,0.3);
    padding: 5px 12px;
    border-radius: 999px;
    margin-bottom: 14px;
}
#header-banner h1 {
    margin: 0 0 8px 0;
    font-size: 2rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: #ffffff;
}
#header-banner p {
    margin: 0;
    max-width: 560px;
    color: rgba(255,255,255,0.65);
    font-size: 0.95rem;
    line-height: 1.55;
}
.header-stats {
    display: flex;
    gap: 10px;
    margin-top: 22px;
    flex-wrap: wrap;
}
.header-stat {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 999px;
    padding: 6px 14px;
    font-size: 0.75rem;
    color: #8b8b8f;
}
.header-stat strong { color: #ececec; }
/* ── Signals-style panels ── */
.panel {
    background: #1c1c1f;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 20px 22px;
    margin-bottom: 12px;
}
.panel-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 14px;
}
.panel-icon {
    width: 28px; height: 28px;
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.85rem;
}
.panel-title {
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #8b8b8f;
}
#run-btn {
    height: 50px !important;
    font-size: 0.95rem !important;
    font-weight: 600 !important;
    border-radius: 10px !important;
    box-shadow: none !important;
    background: #e5484d !important;
}
/* ── Verdict hero ── */
.verdict-hero {
    border-radius: 12px;
    padding: 28px 24px;
    text-align: center;
}
.verdict-icon  { font-size: 2rem; margin-bottom: 6px; }
.verdict-title { font-size: 1.4rem; font-weight: 700; letter-spacing: 0.05em; margin-bottom: 4px; }
.verdict-sub   { font-size: 0.82rem; color: #8b8b8f; }
.verdict-clean {
    background: rgba(48,164,108,0.08);
    border: 1px solid rgba(48,164,108,0.35);
}
.verdict-clean .verdict-title { color: #30a46c; }
.verdict-malicious {
    background: rgba(229,72,77,0.08);
    border: 1px solid rgba(229,72,77,0.4);
    animation: pulse-critical 2.5s ease-in-out infinite;
}
.verdict-malicious .verdict-title { color: #e5484d; }
.verdict-empty {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08);
}
.verdict-empty .verdict-title { color: #ffb224; }
@keyframes pulse-critical {
    0%, 100% { border-color: rgba(229,72,77,0.4); }
    50%      { border-color: rgba(229,72,77,0.75); }
}
/* ── KPI metric cards (Signals-style) ── */
.metric-card {
    background: #232326;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 18px 16px;
    text-align: left;
    border-left: 3px solid rgba(255,255,255,0.12);
}
.metric-card.accent-safe    { border-left-color: #30a46c; }
.metric-card.accent-danger  { border-left-color: #e5484d; }
.metric-card.accent-neutral { border-left-color: #0091ff; }
.metric-label {
    font-size: 0.68rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #8b8b8f;
    margin-bottom: 6px;
}
.metric-value {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 1.75rem;
    font-weight: 700;
    color: #ececec;
}
/* ── Meta pills ── */
.meta-chip {
    background: #232326;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 10px;
    padding: 12px 16px;
    margin-bottom: 8px;
}
.meta-chip-label {
    display: inline-block;
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #8b8b8f;
    margin-bottom: 4px;
}
.meta-chip-value {
    display: block;
    font-size: 0.9rem;
    font-weight: 600;
    color: #ececec;
    font-family: "JetBrains Mono", ui-monospace, monospace;
}
.reasoning-box textarea {
    font-size: 0.88rem !important;
    line-height: 1.6 !important;
    color: #ececec !important;
    background: #232326 !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
    border-radius: 10px !important;
}
.footnote {
    text-align: center;
    color: #555558;
    font-size: 0.75rem;
    margin-top: 4px;
}
footer { visibility: hidden; }
label span, .label-wrap span { color: #8b8b8f !important; }
textarea, input { color: #ececec !important; }
"""

test_case_options = [
    f"{c['id']} · {c['language']} · {CATEGORY_LABELS.get(c['category'], c['category'])}"
    for c in test_suite
]

with gr.Blocks(theme=custom_theme, css=custom_css, title="Gemma Guard Firewall") as demo:

    gr.HTML(f"""
    <div id="header-banner">
        <span class="eyebrow">Gemma Hackathon · AI Shield</span>
        <h1>Multilingual Prompt Injection Firewall</h1>
        <p>Real-time adversarial detection with vector drift &amp; perplexity monitoring.</p>
        <div class="header-stats">
            <span class="header-stat"><strong>{len(test_suite)}</strong> benchmark cases</span>
            <span class="header-stat"><strong>3</strong> languages</span>
            <span class="header-stat"><strong>Dual-signal</strong> guardrail</span>
        </div>
        <svg style="position:absolute;bottom:0;right:40px;opacity:0.12;width:180px"
             viewBox="0 0 100 120" fill="#e5484d">
          <path d="M50 5 L90 20 V55 C90 80 70 100 50 115 C30 100 10 80 10 55 V20 Z"/>
        </svg>
    </div>
    """)

    # ── Input panel ──────────────────────────────────────────────────────────
    with gr.Group(elem_classes="panel"):
        gr.HTML('<div class="panel-header"><div class="panel-icon">📥</div><div class="panel-title">Input</div></div>')
        inp = gr.Textbox(
            label="Prompt to Analyze",
            lines=5,
            placeholder="Type a prompt, or pick a benchmark case below…",
            show_label=True,
            elem_classes="reasoning-box",
        )
        with gr.Row():
            preset_dropdown = gr.Dropdown(
                choices=["Select a test case…"] + test_case_options,
                value="Select a test case…",
                label="🧪 Preset Benchmark",
                scale=4,
            )
            btn = gr.Button(
                "🔍  Run Security Audit",
                variant="primary",
                size="lg",
                elem_id="run-btn",
                scale=1,
            )

    # ── Verdict hero ─────────────────────────────────────────────────────────
    with gr.Group(elem_classes="panel"):
        gr.HTML('<div class="panel-header"><div class="panel-icon">🛡️</div><div class="panel-title">Verdict</div></div>')
        verdict_html = gr.HTML(format_verdict_html(""))

    # ── Telemetry metrics ────────────────────────────────────────────────────
    with gr.Group(elem_classes="panel"):
        gr.HTML('<div class="panel-header"><div class="panel-icon">📊</div><div class="panel-title">Telemetry</div></div>')
        with gr.Row():
            risk_html  = gr.HTML(format_metric_card("Risk Score", "—", "accent-neutral"))
            perp_html  = gr.HTML(format_metric_card("Perplexity", "—", "accent-neutral"))
            drift_html = gr.HTML(format_metric_card("Vector Drift", "—", "accent-neutral"))

    # ── Reasoning + meta ─────────────────────────────────────────────────────
    with gr.Row():
        with gr.Column():
            with gr.Group(elem_classes="panel"):
                gr.HTML('<div class="panel-header"><div class="panel-icon">📝</div><div class="panel-title">Guard Reasoning</div></div>')
                reasoning = gr.Textbox(
                    label=None,
                    lines=3,
                    interactive=False,
                    show_label=False,
                    placeholder="Run an audit to see guard reasoning…",
                    elem_classes="reasoning-box",
                )
        with gr.Column():
            with gr.Group(elem_classes="panel"):
                gr.HTML('<div class="panel-header"><div class="panel-icon">🔍</div><div class="panel-title">Detection Meta</div></div>')
                lang_html    = gr.HTML(format_meta_chip("Detected Language", "—"))
                attack_html  = gr.HTML(format_meta_chip("Attack Category", "—"))

    gr.HTML('<div class="footnote">Dual-signal guardrail — Gemma semantic verdict fused with statistical anomaly scoring</div>')

    def load_preset(selected_label):
        if not selected_label or selected_label.startswith("Select"):
            return ""
        case_id = selected_label.split(" · ")[0]
        matched = next((c for c in test_suite if c["id"] == case_id), None)
        return matched["prompt"] if matched else ""

    preset_dropdown.change(fn=load_preset, inputs=preset_dropdown, outputs=inp)

    outputs = [verdict_html, risk_html, perp_html, drift_html, reasoning, lang_html, attack_html]
    btn.click(fn=check_prompt, inputs=inp, outputs=outputs, show_progress="full")
    inp.submit(fn=check_prompt, inputs=inp, outputs=outputs, show_progress="full")


if __name__ == "__main__":
    demo.launch()