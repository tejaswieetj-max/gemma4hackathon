import os
import re
import base64
import gradio as gr

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
            return "[ERROR] pypdf not installed — cannot read PDF. Run: pip install pypdf --break-system-packages"
        except Exception as e:
            return f"[ERROR] Failed to read PDF: {e}"

    if ext == ".docx":
        try:
            import docx
            d = docx.Document(file_path)
            return "\n".join(p.text for p in d.paragraphs)
        except ImportError:
            return "[ERROR] python-docx not installed — cannot read DOCX. Run: pip install python-docx --break-system-packages"
        except Exception as e:
            return f"[ERROR] Failed to read DOCX: {e}"

    # Fallback: try reading as plain text regardless of extension
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        return f"[ERROR] Unsupported or unreadable file: {e}"


# ---------------------------------------------------------------------------
# Hidden-content detection
# ---------------------------------------------------------------------------
ZERO_WIDTH_CHARS = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"]

MALICIOUS_KEYWORDS = [
    "dan",
    "ignore",
    "disregard",
    "pick a lock",
    "maranthuko",
    "bhool jao",
    "bypassing",
    "bypass",
    "explosive",
    "admin password",
    "developer mode",
    "override",
    "secret",
    "token",
    "attacker.com",
    "thalli",
    "system prompt",
    "reveal your instructions",
]

TANGLISH_MARKERS = ["maranthuko", "sollu", "mami", "nanba", "machan", "thalli", "anna"]
HINGLISH_MARKERS = ["bhool jao", "batao", "samjha do", "banao", "purani", "purana"]


def find_zero_width_chars(text: str) -> list:
    found = []
    for ch in ZERO_WIDTH_CHARS:
        if ch in text:
            found.append(f"U+{ord(ch):04X}")
    return found


def find_and_decode_base64(text: str) -> list:
    """Find base64-looking substrings (20+ chars) and try to decode them."""
    candidates = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
    decoded_hits = []
    for c in candidates:
        try:
            decoded = base64.b64decode(c, validate=True).decode("utf-8", errors="strict")
            # only keep it if it decodes to plausible readable text
            if decoded.isprintable() and len(decoded) > 3:
                decoded_hits.append({"encoded": c, "decoded": decoded})
        except Exception:
            continue
    return decoded_hits


def detect_language(text: str) -> str:
    text_lower = text.lower()
    if any(kw in text_lower for kw in TANGLISH_MARKERS):
        return "Tanglish"
    if any(kw in text_lower for kw in HINGLISH_MARKERS):
        return "Hinglish"
    return "English"


def contains_malicious_keywords(text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in MALICIOUS_KEYWORDS)


def scan_document(file):
    if file is None:
        return (
            format_verdict_html("EMPTY"),
            "No document uploaded.",
            "",  # language hidden when not malicious/empty
        )

    text = extract_text_from_file(file.name)

    if text.startswith("[ERROR]"):
        return (
            format_verdict_html("ERROR"),
            text,
            "",
        )

    # 1. Check visible text for direct/roleplay injection keywords
    visible_flagged = contains_malicious_keywords(text)

    # 2. Check for zero-width / invisible unicode characters (a real hiding technique)
    zero_width_found = find_zero_width_chars(text)

    # 3. Find and decode base64 blocks, check decoded content for injection intent
    decoded_blocks = find_and_decode_base64(text)
    decoded_flagged = any(contains_malicious_keywords(b["decoded"]) for b in decoded_blocks)

    is_malicious = visible_flagged or decoded_flagged or bool(zero_width_found)

    # Build the "hidden text" report
    hidden_report_parts = []
    if zero_width_found:
        hidden_report_parts.append(
            f"⚠️ Invisible/zero-width Unicode characters detected: {', '.join(zero_width_found)}\n"
            "These characters render as blank space but can be used to smuggle hidden instructions "
            "or break up flagged keywords to dodge simple filters."
        )
    if decoded_blocks:
        for b in decoded_blocks:
            flag = "🚨 MALICIOUS CONTENT" if contains_malicious_keywords(b["decoded"]) else "benign"
            hidden_report_parts.append(
                f"🔐 Base64 block decoded ({flag}):\n"
                f"   Encoded: {b['encoded'][:60]}{'...' if len(b['encoded']) > 60 else ''}\n"
                f"   Decoded: \"{b['decoded']}\""
            )
    if visible_flagged and not decoded_blocks and not zero_width_found:
        hidden_report_parts.append(
            "🚨 Suspicious instruction-override language detected directly in the visible document text "
            "(e.g. 'ignore previous instructions', 'developer mode', 'reveal system prompt')."
        )
    if not hidden_report_parts:
        hidden_report_parts.append("✅ No hidden or obfuscated content detected in this document.")

    hidden_text_report = "\n\n".join(hidden_report_parts)

    verdict_key = "MALICIOUS" if is_malicious else "CLEAN"
    language_display = detect_language(text) if is_malicious else ""

    return (
        format_verdict_html(verdict_key),
        hidden_text_report,
        format_language_html(language_display) if is_malicious else "",
    )


# ---------------------------------------------------------------------------
# UI formatting (Very Pretty Light Blue Gradient + Crisp White Cards)
# ---------------------------------------------------------------------------
def format_verdict_html(kind: str) -> str:
    if kind == "EMPTY":
        return """
        <div class="verdict-hero verdict-empty">
            <div class="verdict-icon">⚠️</div>
            <div class="verdict-title">No Document</div>
            <div class="verdict-sub">Upload a file to scan.</div>
        </div>
        """
    if kind == "ERROR":
        return """
        <div class="verdict-hero verdict-empty">
            <div class="verdict-icon">⚠️</div>
            <div class="verdict-title">Read Error</div>
            <div class="verdict-sub">Could not process this file — see details below.</div>
        </div>
        """
    if kind == "MALICIOUS":
        return """
        <div class="verdict-hero verdict-malicious">
            <div class="verdict-icon">⛔</div>
            <div class="verdict-title">MALICIOUS</div>
            <div class="verdict-sub">Hidden or adversarial content detected in this document</div>
        </div>
        """
    return """
    <div class="verdict-hero verdict-clean">
        <div class="verdict-icon">✅</div>
        <div class="verdict-title">CLEAN</div>
        <div class="verdict-sub">No injection or hidden-content signals detected</div>
    </div>
    """


def format_language_html(language: str) -> str:
    if not language:
        return ""
    return f"""
    <div class="meta-chip">
        <span class="meta-chip-label">Detected Language</span>
        <span class="meta-chip-value">{language}</span>
    </div>
    """


custom_theme = gr.themes.Base(
    primary_hue="sky",
    secondary_hue="slate",
    neutral_hue="slate",
    font=[gr.themes.GoogleFont("Inter"), "ui-sans-serif", "system-ui"],
    font_mono=[gr.themes.GoogleFont("JetBrains Mono"), "ui-monospace"],
).set(
    body_background_fill="linear-gradient(135deg, #e0f2fe 0%, #f0f7ff 50%, #e8f4fe 100%)",
    block_background_fill="#ffffff",
    block_border_width="1px",
    block_radius="16px",
    block_label_text_color="#475569",
    body_text_color="#0f172a",
    input_background_fill="#ffffff",
    input_border_color="#bae6fd",
    button_primary_background_fill="#0284c7",
    button_primary_background_fill_hover="#0369a1",
    button_primary_text_color="#ffffff",
)

custom_css = """
* { box-sizing: border-box; }
.gradio-container {
    max-width: 920px !important;
    background: linear-gradient(135deg, #e0f2fe 0%, #f0f7ff 50%, #e8f4fe 100%) !important;
    font-family: 'Inter', system-ui, sans-serif !important;
    color: #0f172a !important;
}

#header-banner {
    position: relative;
    overflow: hidden;
    background: #ffffff !important;
    border-radius: 20px;
    padding: 38px 42px;
    margin-bottom: 20px;
    border: 1px solid #bae6fd;
    box-shadow: 0 12px 32px -8px rgba(2, 132, 199, 0.12), 0 4px 12px rgba(0, 0, 0, 0.03);
}

#header-banner::before {
    content: "";
    position: absolute;
    top: 0; right: 0; bottom: 0; left: 0;
    background-image: radial-gradient(rgba(2, 132, 199, 0.08) 1px, transparent 1px);
    background-size: 20px 20px;
    pointer-events: none;
    opacity: 0.6;
}

#header-banner .eyebrow {
    display: inline-block;
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: #0284c7;
    background: #e0f2fe;
    border: 1px solid #bae6fd;
    padding: 6px 14px;
    border-radius: 999px;
    margin-bottom: 14px;
}

#header-banner h1 {
    margin: 0 0 8px 0;
    font-size: 2rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: #0f172a;
}

#header-banner p {
    margin: 0;
    max-width: 580px;
    color: #475569;
    font-size: 0.96rem;
    line-height: 1.6;
}

.panel {
    background: #ffffff !important;
    border: 1px solid #bae6fd !important;
    border-radius: 18px !important;
    padding: 24px 26px !important;
    margin-bottom: 16px !important;
    box-shadow: 0 8px 24px -4px rgba(2, 132, 199, 0.08), 0 2px 6px rgba(0,0,0,0.02) !important;
}

.panel-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
    padding-bottom: 10px;
    border-bottom: 1px solid #f0f7ff;
}

.panel-icon {
    width: 32px; height: 32px;
    background: #e0f2fe;
    border: 1px solid #bae6fd;
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.9rem;
}

.panel-title {
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #0369a1;
}

#run-btn {
    height: 52px !important;
    font-size: 0.98rem !important;
    font-weight: 700 !important;
    border-radius: 12px !important;
    box-shadow: 0 6px 20px rgba(2, 132, 199, 0.25) !important;
    background: linear-gradient(135deg, #0284c7 0%, #2563eb 100%) !important;
    color: #ffffff !important;
    border: none !important;
    transition: all 0.2s ease !important;
}

#run-btn:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 8px 25px rgba(2, 132, 199, 0.4) !important;
}

.verdict-hero {
    border-radius: 14px;
    padding: 28px 24px;
    text-align: center;
}

.verdict-icon  { font-size: 2.2rem; margin-bottom: 6px; }
.verdict-title { font-size: 1.45rem; font-weight: 800; letter-spacing: 0.04em; margin-bottom: 4px; }
.verdict-sub   { font-size: 0.88rem; color: #475569; }

.verdict-clean {
    background: #ecfdf5;
    border: 1px solid #a7f3d0;
}

.verdict-clean .verdict-title { color: #047857; }

.verdict-malicious {
    background: #fef2f2;
    border: 1px solid #fecaca;
    animation: pulse-critical 2.5s ease-in-out infinite;
}

.verdict-malicious .verdict-title { color: #dc2626; }

.verdict-empty {
    background: #f0f9ff;
    border: 1px solid #bae6fd;
}

.verdict-empty .verdict-title { color: #0284c7; }

@keyframes pulse-critical {
    0%, 100% { border-color: rgba(239, 68, 68, 0.4); }
    50%      { border-color: rgba(239, 68, 68, 0.85); }
}

.meta-chip {
    background: #f0f9ff;
    border: 1px solid #bae6fd;
    border-radius: 12px;
    padding: 12px 18px;
    margin-top: 10px;
}

.meta-chip-label {
    display: inline-block;
    font-size: 0.68rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #0369a1;
    margin-bottom: 4px;
}

.meta-chip-value {
    display: block;
    font-size: 0.95rem;
    font-weight: 700;
    color: #0f172a;
    font-family: "JetBrains Mono", ui-monospace, monospace;
}

.hidden-box textarea {
    font-size: 0.88rem !important;
    line-height: 1.65 !important;
    color: #0f172a !important;
    background: #f8fafc !important;
    border: 1px solid #cbd5e1 !important;
    border-radius: 12px !important;
    font-family: "JetBrains Mono", ui-monospace, monospace !important;
}

.footnote {
    text-align: center;
    color: #475569;
    font-size: 0.78rem;
    margin-top: 6px;
    font-weight: 500;
}

footer { visibility: hidden; }
label span, .label-wrap span { color: #334155 !important; font-weight: 600 !important; }
"""

with gr.Blocks(theme=custom_theme, css=custom_css, title="Document Injection Scanner") as demo:

    gr.HTML("""
    <div id="header-banner">
        <span class="eyebrow">Gemma Hackathon · AI Shield</span>
        <h1>Document Injection Scanner</h1>
        <p>Upload a document. We scan the visible content and any hidden or obfuscated
        payloads — zero-width characters, base64-encoded instructions — for injection attempts.</p>
    </div>
    """)

    with gr.Group(elem_classes="panel"):
        gr.HTML('<div class="panel-header"><div class="panel-icon">📄</div><div class="panel-title">Upload Document</div></div>')
        file_input = gr.File(
            label="Document (.txt, .md, .pdf, .docx)",
            file_types=[".txt", ".md", ".pdf", ".docx", ".csv", ".log"],
        )
        btn = gr.Button("🔍  Scan Document", variant="primary", size="lg", elem_id="run-btn")

    with gr.Group(elem_classes="panel"):
        gr.HTML('<div class="panel-header"><div class="panel-icon">🛡️</div><div class="panel-title">Verdict</div></div>')
        verdict_html = gr.HTML(format_verdict_html("EMPTY"))
        language_html = gr.HTML("")

    with gr.Group(elem_classes="panel"):
        gr.HTML('<div class="panel-header"><div class="panel-icon">🕵️</div><div class="panel-title">Hidden / Obfuscated Content</div></div>')
        hidden_text_box = gr.Textbox(
            label=None,
            show_label=False,
            lines=6,
            interactive=False,
            placeholder="Scan a document to see any hidden or obfuscated content found…",
            elem_classes="hidden-box",
        )

    gr.HTML('<div class="footnote">Detects direct keyword-based injection, zero-width character smuggling, and base64-obfuscated payloads</div>')

    btn.click(
        fn=scan_document,
        inputs=file_input,
        outputs=[verdict_html, hidden_text_box, language_html],
        show_progress="full",
    )

if __name__ == "__main__":
    demo.launch()