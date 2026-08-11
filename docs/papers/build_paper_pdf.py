"""Build the Weft preprint PDF: pandoc -> styled HTML -> headless Chrome print-to-pdf.

Matches the approved pipeline (not plain pandoc/LaTeX). Single column, selectable
text, navy/accent palette, clean academic typography.
"""
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).parent
SRC = HERE.parent / "weft-whitepaper.md"
HTML_OUT = HERE / "zenodo-bundle" / "weft-whitepaper.html"
PDF_OUT = HERE / "zenodo-bundle" / "weft-whitepaper.pdf"
PANDOC = "pandoc"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

body = subprocess.run(
    [PANDOC, str(SRC), "-f", "markdown+hard_line_breaks", "-t", "html5"],
    capture_output=True, text=True, encoding="utf-8", check=True,
).stdout

# Header zone = everything before the first <h2> (title + byline + rule).
idx = body.find("<h2")
head, rest = body[:idx], body[idx:]
head = head.replace("<hr />", "").replace("<hr>", "")
# first <p> after the title is the byline
head = re.sub(r"<p>", '<p class="byline">', head, count=1)
header_html = f'<header class="hdr">{head}</header>'

CSS = """
@page { size: Letter; margin: 0.9in 0.95in; }
* { box-sizing: border-box; }
body {
  font-family: "Charter","Georgia","Times New Roman",serif;
  font-size: 10.8pt; line-height: 1.5; color: #1f2328; margin: 0;
  -webkit-print-color-adjust: exact; print-color-adjust: exact;
}

/* Title block */
.hdr { text-align: center; margin: 0 0 18pt; padding-bottom: 12pt;
  border-bottom: 2px solid #10314f; }
.hdr h1 { font-size: 19pt; font-weight: 700; color: #10314f;
  line-height: 1.25; margin: 0 0 8pt; letter-spacing: .2px; }
.hdr .byline { font-size: 10pt; color: #44505c; line-height: 1.7; margin: 0; }
.hdr .byline a { color: #2f6da3; text-decoration: none; }

/* Section headings */
h2 { font-size: 13pt; font-weight: 700; color: #10314f; margin: 18pt 0 7pt;
  padding-bottom: 3pt; border-bottom: 1px solid #d8e0e8;
  break-after: avoid; page-break-after: avoid; }
h3 { font-size: 11.2pt; font-weight: 700; color: #1f4e79; margin: 13pt 0 5pt;
  break-after: avoid; page-break-after: avoid; }

/* Abstract: first h2 (Abstract) + following paragraph styled as a lead block */
h2#abstract + p, h2:first-of-type + p { }

p { margin: 0 0 8pt; text-align: justify; }
strong { color: #10314f; }
em { color: #1f2328; }
a { color: #2f6da3; text-decoration: none; }

/* Lists */
ul, ol { margin: 4pt 0 9pt; padding-left: 20pt; }
li { margin: 0 0 4pt; }
li::marker { color: #2f6da3; }

/* Tables */
table { border-collapse: collapse; width: 100%; margin: 8pt 0 12pt;
  font-size: 10pt; break-inside: avoid; page-break-inside: avoid; }
th { background: #10314f; color: #fff; font-weight: 600; text-align: left;
  padding: 5pt 9pt; }
td { padding: 5pt 9pt; border-bottom: 1px solid #e2e8ef; vertical-align: top; }
tr:nth-child(even) td { background: #f5f8fb; }

/* Code */
code { font-family: "Consolas","SF Mono",monospace; font-size: 9.2pt;
  background: #eef2f6; color: #1f3a52; padding: 1pt 4pt; border-radius: 3px; }
pre { background: #0f1722; color: #e6edf3; padding: 11pt 13pt; border-radius: 6px;
  overflow-x: auto; font-size: 9pt; line-height: 1.45; margin: 8pt 0 12pt;
  break-inside: avoid; page-break-inside: avoid; }
pre code { background: none; color: inherit; padding: 0; font-size: 9pt; }

hr { border: none; border-top: 1px solid #d8e0e8; margin: 16pt 0; }

/* Figures */
img { max-width: 100%; display: block; margin: 10pt auto 4pt; }
figure { margin: 12pt 0; break-inside: avoid; page-break-inside: avoid; }
figcaption, p > img + em, .caption { font-size: 9pt; color: #5a6470; text-align: center; }
p:has(> img) { text-align: center; font-size: 9pt; color: #5a6470;
  break-inside: avoid; page-break-inside: avoid; }

/* Keep the section headers with their first lines */
h2, h3 { orphans: 3; widows: 3; }
"""

template = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Weft: Evidence-Gated Version Control for Autonomous Agent Swarms</title>
<style>{CSS}</style></head>
<body>
{header_html}
{rest}
</body></html>
"""

HTML_OUT.write_text(template, encoding="utf-8")
print("HTML written:", HTML_OUT)

subprocess.run(
    [CHROME, "--headless", "--disable-gpu", "--no-pdf-header-footer",
     f"--print-to-pdf={PDF_OUT}", HTML_OUT.as_uri()],
    check=True, capture_output=True,
)
print("PDF written:", PDF_OUT)
