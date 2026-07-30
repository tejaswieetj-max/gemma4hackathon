import os
import re
import base64
import requests
import gradio as gr

API_URL = "http://localhost:8000/api/v1/check"

# ---------------------------------------------------------------------------
# Text extraction from uploaded documents
# ---------------------------------------------------------------------------
def extract_text_from_file(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()

    if ext in [".txt", ".md", ".csv", ".log"]:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    if ext == ".pdf":
        try:
            from pypdf import PdfReader
            reader = PdfReader(file_path)
            return "\n".join(page.extract_text() or "" for page in reader.pages)
        except ImportError:
            return "[ERROR] pypdf not installed — run: pip install pypdf"
        except Exception as e:
            return f"[ERROR] Failed to read PDF: {e}"

    if ext == ".docx":
        try:
            import docx
            d = docx.Document(file_path)
            return "\n".join(p.text for p in d.paragraphs)
        except ImportError:
            return "[ERROR] python-docx not installed — run: pip install python-docx"
        except Exception as e:
            return f"[ERROR] Failed to read DOCX: {e}"

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        return f"[ERROR] Unsupported or unreadable file: {e}"


# ---------------------------------------------------------------------------
# Hidden-content detection & Server Integration
# ---------------------------------------------------------------------------
ZERO_WIDTH_CHARS = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"]

def find_zero_width_chars(text: str) -> list:
    return [f"U+{ord(ch):04X}" for ch in ZERO_WIDTH_CHARS if ch in text]

def find_and_decode_base64(text: str) -> list:
    candidates = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
    decoded_hits = []
    for c in candidates:
        try:
            decoded = base64.b64decode(c, validate=True).decode("utf-8", errors="strict")
            if decoded.isprintable() and len(decoded) > 3:
                decoded_hits.append({"encoded": c, "decoded": decoded})
        except Exception:
            continue
    return decoded_hits

def scan_document(file):
    if file is None:
        return (
            format_verdict_html("EMPTY"),
            "No document uploaded.",
            "",
        )

    text = extract_text_from_file(file.name)

    if text.startswith("[ERROR]"):
        return (
            format_verdict_html("ERROR"),
            text,
            "",
        )

    # Local pre-checks for hidden payload techniques
    zero_width_found = find_zero_width_chars(text)
    decoded_blocks = find_and_decode_base64(text)

    # Pass text to GemmaSentinel-X Backend Engine
    try:
        response = requests.post(
            API_URL,
            json={"source": "rag_document", "text": text},
            timeout=10
        ).json()
        
        status = response.get("status", "CLEAN")
        guard_data = response.get("guard", {})
        language_display = guard_data.get("detected_language", "English")
        reasoning = guard_data.get("reasoning", "No anomaly detected.")
    except Exception as e:
        # Fallback if backend server is offline
        status = "CLEAN"
        language_display = "Unknown"
        reasoning = f"Backend unavailable ({e}). Defaulting to offline mode."

    is_malicious = (status == "BLOCKED") or bool(zero_width_found) or bool(decoded_blocks)

    # Build report
    hidden_report_parts = []
    if zero_width_found:
        hidden_report_parts.append(
            f"⚠️ Invisible/zero-width Unicode characters detected: {', '.join(zero_width_found)}"
        )
    if decoded_blocks:
        for b in decoded_blocks:
            hidden_report_parts.append(
                f"🔐 Base64 block decoded:\n  Encoded: {b['encoded'][:60]}...\n  Decoded: \"{b['decoded']}\""
            )
    
    hidden_report_parts.append(f"🛡️ GemmaSentinel Engine Reasoning: {reasoning}")
    hidden_text_report = "\n\n".join(hidden_report_parts)

    verdict_key = "MALICIOUS" if is_malicious else "CLEAN"

    return (
        format_verdict_html(verdict_key),
        hidden_text_report,
        format_language_html(language_display if is_malicious else ""),
    )


# ---------------------------------------------------------------------------
# UI Formatting
# ---------------------------------------------------------------------------
def format_verdict_html(kind: str) -> str:
    if kind == "EMPTY":
        return '<div class="verdict-hero verdict-empty"><div class="verdict-icon">⚠️</div><div class="verdict-title">No Document</div><div class="verdict-sub">Upload a file to scan.</div></div>'
    if kind == "ERROR":
        return '<div class="verdict-hero verdict-empty"><div class="verdict-icon">⚠️</div><div class="verdict-title">Read Error</div><div class="verdict-sub">Could not process this file.</div></div>'
    if kind == "MALICIOUS":
        return '<div class="verdict-hero verdict-malicious"><div class="verdict-icon">⛔</div><div class="verdict-title">MALICIOUS</div><div class="verdict-sub">Adversarial payload detected by GemmaSentinel-X</div></div>'
    return '<div class="verdict-hero verdict-clean"><div class="verdict-icon">✅</div><div class="verdict-title">CLEAN</div><div class="verdict-sub">No injection signals detected</div></div>'

def format_language_html(language: str) -> str:
    if not language:
        return ""
    return f'<div class="meta-chip"><span class="meta-chip-label">Detected Language</span><span class="meta-chip-value">{language}</span></div>'

# ---------------------------------------------------------------------------
# Theme — deep-space glassmorphism palette
# ---------------------------------------------------------------------------
custom_theme = gr.themes.Base(
    primary_hue="violet",
    secondary_hue="cyan",
    neutral_hue="slate",
    font=[gr.themes.GoogleFont("Inter"), "ui-sans-serif", "system-ui"],
    font_mono=[gr.themes.GoogleFont("JetBrains Mono"), "ui-monospace"],
).set(
    body_background_fill="radial-gradient(circle at 15% 10%, #2a1e5c 0%, #150f33 32%, #0a0a18 68%, #050510 100%)",
    block_background_fill="rgba(255,255,255,0.055)",
    block_border_width="1px",
    block_border_color="rgba(255,255,255,0.12)",
    block_radius="18px",
    body_text_color="#e6e4fb",
    block_label_text_color="#b8b3e8",
    input_background_fill="rgba(255,255,255,0.05)",
    button_primary_background_fill="linear-gradient(135deg, #7c3aed 0%, #22d3ee 100%)",
    button_primary_text_color="#0a0a18",
)

custom_css = """
:root {
    --glass-fill: rgba(255,255,255,0.055);
    --glass-border: rgba(255,255,255,0.14);
    --glow-violet: rgba(139,92,246,0.35);
    --glow-cyan: rgba(34,211,238,0.30);
}

body, .gradio-container {
    background: radial-gradient(circle at 15% 10%, #2a1e5c 0%, #150f33 32%, #0a0a18 68%, #050510 100%) !important;
}

/* faint ambient glow orbs behind the glass, purely decorative */
.gradio-container::before {
    content: "";
    position: fixed;
    top: -10%;
    left: -10%;
    width: 45%;
    height: 45%;
    background: radial-gradient(circle, var(--glow-violet) 0%, transparent 70%);
    filter: blur(60px);
    pointer-events: none;
    z-index: 0;
}
.gradio-container::after {
    content: "";
    position: fixed;
    bottom: -15%;
    right: -10%;
    width: 50%;
    height: 50%;
    background: radial-gradient(circle, var(--glow-cyan) 0%, transparent 70%);
    filter: blur(70px);
    pointer-events: none;
    z-index: 0;
}

h1 {
    font-weight: 800;
    letter-spacing: -0.02em;
    background: linear-gradient(135deg, #ffffff 0%, #c4b5fd 55%, #67e8f9 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    padding-bottom: 4px;
}

/* Glass panels for every block (upload card, results card, textbox wrapper) */
.block, .form {
    background: var(--glass-fill) !important;
    border: 1px solid var(--glass-border) !important;
    border-radius: 18px !important;
    backdrop-filter: blur(18px) saturate(140%);
    -webkit-backdrop-filter: blur(18px) saturate(140%);
    box-shadow: 0 8px 32px rgba(0,0,0,0.35), inset 0 1px 0 rgba(255,255,255,0.06);
}

.verdict-hero {
    border-radius: 16px;
    padding: 26px;
    text-align: center;
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    border: 1px solid var(--glass-border);
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.08);
}
.verdict-clean {
    background: rgba(16,185,129,0.12);
    border-color: rgba(52,211,153,0.35);
    color: #6ee7b7;
}
.verdict-malicious {
    background: rgba(244,63,94,0.14);
    border-color: rgba(251,113,133,0.4);
    color: #fca5b1;
}
.verdict-empty {
    background: rgba(56,189,248,0.10);
    border-color: rgba(103,232,249,0.35);
    color: #7dd3fc;
}
.verdict-title { font-size: 1.45rem; font-weight: 800; letter-spacing: -0.01em; }
.verdict-sub { color: rgba(230,228,251,0.65); font-size: 0.9rem; margin-top: 4px; }

.meta-chip {
    background: rgba(139,92,246,0.12);
    border: 1px solid rgba(196,181,253,0.3);
    border-radius: 12px;
    padding: 10px 16px;
    margin-top: 10px;
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
}
.meta-chip-label { font-size: 0.7rem; font-weight: 700; color: #a5b4fc; text-transform: uppercase; letter-spacing: 0.04em; }
.meta-chip-value { font-size: 0.95rem; font-weight: 700; font-family: monospace; color: #e6e4fb; }

textarea, input {
    background: rgba(255,255,255,0.04) !important;
    color: #e6e4fb !important;
    border-color: var(--glass-border) !important;
}

button.primary {
    box-shadow: 0 4px 20px rgba(124,58,237,0.4);
}
"""

with gr.Blocks(theme=custom_theme, css=custom_css, title="Document Injection Scanner") as demo:
    gr.HTML('<h1>GemmaSentinel-X: Document Injection Scanner</h1>')
    
    with gr.Row():
        with gr.Column():
            file_input = gr.File(label="Upload Document (.txt, .md, .pdf, .docx)")
            btn = gr.Button("🔍 Scan Document", variant="primary")
        with gr.Column():
            verdict_html = gr.HTML(format_verdict_html("EMPTY"))
            language_html = gr.HTML("")
            hidden_text_box = gr.Textbox(label="Analysis & Inspection Report", lines=6, interactive=False)

    btn.click(
        fn=scan_document,
        inputs=file_input,
        outputs=[verdict_html, hidden_text_box, language_html],
    )

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)