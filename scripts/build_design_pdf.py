"""Render docs/DESIGN.md to a polished PDF (docs/submission/DESIGN.pdf).

The design doc embeds Mermaid diagrams as ```mermaid fenced blocks. Those don't
render in a plain Markdown->PDF, so we swap each block (in document order) for its
pre-rendered PNG from docs/diagrams/ — the i-th mermaid block maps 1:1 to diagram
0(i+1). Then: Markdown -> HTML (python-markdown) -> PDF (WeasyPrint) with a print
stylesheet.

Run inside the project's PDF venv:
    . .venv-pdf/bin/activate
    DYLD_FALLBACK_LIBRARY_PATH="$(brew --prefix)/lib" python scripts/build_design_pdf.py
"""
from __future__ import annotations

import re
from pathlib import Path

import markdown
from weasyprint import HTML

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "DESIGN.md"
DIAGRAMS = ROOT / "docs" / "diagrams"
OUT = ROOT / "docs" / "submission" / "DESIGN.pdf"

# The 7 ```mermaid blocks in DESIGN.md, in document order, map to these PNGs.
DIAGRAM_ORDER = [
    "01-high-level-architecture",
    "02-membership-model",
    "03-access-control-model",
    "04-data-model-erd",
    "05-auth-authz-sequence",
    "06-tenant-isolation",
    "07-service-to-service",
]

CSS = """
@page { size: A4; margin: 18mm 16mm; @bottom-center { content: counter(page) " / " counter(pages); font-size: 9px; color: #888; } }
body { font-family: -apple-system, "Helvetica Neue", Arial, sans-serif; font-size: 10.5px; line-height: 1.5; color: #1a1a1a; }
h1 { font-size: 22px; border-bottom: 2px solid #333; padding-bottom: 6px; }
h2 { font-size: 16px; margin-top: 1.4em; border-bottom: 1px solid #ddd; padding-bottom: 3px; page-break-after: avoid; }
h3 { font-size: 13px; margin-top: 1.1em; page-break-after: avoid; }
h2, h3, h4 { page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; margin: 0.8em 0; font-size: 9.3px; page-break-inside: avoid; }
th, td { border: 1px solid #ccc; padding: 4px 7px; text-align: left; vertical-align: top; }
th { background: #f2f2f2; }
code { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 9px; background: #f4f4f4; padding: 1px 3px; border-radius: 3px; }
pre { background: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 5px; padding: 9px 11px; overflow-x: auto; page-break-inside: avoid; }
pre code { background: none; padding: 0; font-size: 8.6px; line-height: 1.4; }
img { max-width: 100%; height: auto; display: block; margin: 0.8em auto; page-break-inside: avoid; }
blockquote { border-left: 3px solid #ccc; margin: 0.8em 0; padding: 0.1em 0.9em; color: #555; background: #fafafa; }
a { color: #0b5; text-decoration: none; }
hr { border: none; border-top: 1px solid #ddd; margin: 1.2em 0; }
"""

MERMAID_RE = re.compile(r"```mermaid\b.*?```", re.DOTALL)


def replace_mermaid_with_images(md_text: str) -> str:
    """Swap each ```mermaid block (in order) for its rendered PNG (absolute file URL)."""
    blocks = MERMAID_RE.findall(md_text)
    if len(blocks) != len(DIAGRAM_ORDER):
        raise SystemExit(
            f"Expected {len(DIAGRAM_ORDER)} mermaid blocks, found {len(blocks)} in {SRC}. "
            "Update DIAGRAM_ORDER if the diagram set changed."
        )
    counter = {"i": 0}

    def _sub(_match: re.Match) -> str:
        name = DIAGRAM_ORDER[counter["i"]]
        counter["i"] += 1
        png = (DIAGRAMS / f"{name}.png").resolve()
        if not png.exists():
            raise SystemExit(f"Missing rendered diagram: {png} (run `make diagrams`).")
        return f"![{name}]({png.as_uri()})"

    return MERMAID_RE.sub(_sub, md_text)


def main() -> None:
    md_text = SRC.read_text(encoding="utf-8")
    md_text = replace_mermaid_with_images(md_text)

    html_body = markdown.markdown(
        md_text,
        extensions=["extra", "tables", "fenced_code", "sane_lists", "toc"],
    )
    html_doc = f"<!doctype html><html><head><meta charset='utf-8'>" \
               f"<style>{CSS}</style></head><body>{html_body}</body></html>"

    OUT.parent.mkdir(parents=True, exist_ok=True)
    # base_url lets any remaining relative links resolve against docs/.
    HTML(string=html_doc, base_url=str(SRC.parent)).write_pdf(str(OUT))
    print(f"[pdf] wrote {OUT.relative_to(ROOT)}  ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
