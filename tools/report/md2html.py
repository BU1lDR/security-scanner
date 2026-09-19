"""Minimal Markdown -> HTML for the sample report, so a headless browser can
print it to PDF.

Deliberately not a general Markdown implementation and not a dependency: it
handles exactly the constructs the report uses (headings, tables, fenced code,
bold, inline code, links, lists, rules) and nothing else. The build spec says
not to polish the PDF design, so the CSS is print defaults plus enough to keep
tables and code blocks from breaking across pages badly.
"""

from __future__ import annotations

import html
import re
import sys

CSS = """
@page { size: A4; margin: 18mm 16mm; }
body { font: 10.5pt/1.48 "Georgia","Times New Roman",serif; color:#111; max-width:none; }
h1 { font-size:19pt; margin:0 0 .3em; page-break-before:always; border-bottom:2px solid #111; padding-bottom:.2em; }
h1:first-of-type { page-break-before:avoid; }
h2 { font-size:13pt; margin:1.4em 0 .4em; page-break-after:avoid; }
h3 { font-size:11pt; margin:1.1em 0 .35em; page-break-after:avoid; }
p, li { orphans:3; widows:3; }
table { border-collapse:collapse; width:100%; margin:.8em 0; font-size:9pt; page-break-inside:avoid; }
th, td { border:1px solid #999; padding:4px 6px; text-align:left; vertical-align:top; }
th { background:#eee; }
pre { background:#f5f5f5; border:1px solid #ddd; padding:7px 9px; font:8.5pt/1.35 "Consolas",monospace;
      white-space:pre-wrap; page-break-inside:avoid; }
code { font:9pt "Consolas",monospace; background:#f2f2f2; padding:0 2px; }
pre code { background:none; padding:0; font-size:8.5pt; }
hr { border:0; border-top:1px solid #bbb; margin:1.5em 0; }
a { color:#111; text-decoration:none; }
strong { font-weight:700; }
"""

BREAK = "\x00"   # stands in for <br> through the escaping pass

_INLINE = (
    (re.compile(r"`([^`]+)`"), lambda m: f"<code>{html.escape(m.group(1))}</code>"),
    (re.compile(r"\*\*([^*]+)\*\*"), lambda m: f"<strong>{m.group(1)}</strong>"),
    (re.compile(r"\[([^\]]+)\]\(([^)]+)\)"), lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>'),
    # Single-asterisk emphasis, applied after bold so the ** pairs are already
    # consumed. Without this the report's cited document titles and its
    # deliberate contrasts render as literal asterisks in the PDF.
    (re.compile(r"(?<![*\w])\*([^*\n]+?)\*(?![*\w])"), lambda m: f"<em>{m.group(1)}</em>"),
)


def inline(text: str) -> str:
    """Escape, then re-apply inline markup. Code spans are escaped first so a
    literal ``<`` inside one survives, and ``**`` inside a code span is left
    alone because the code pattern consumes it."""
    out, last = [], 0
    for m in re.finditer(r"`[^`]+`", text):
        out.append(html.escape(text[last:m.start()]))
        out.append(f"<code>{html.escape(m.group(0)[1:-1])}</code>")
        last = m.end()
    out.append(html.escape(text[last:]))
    joined = "".join(out)
    for pat, repl in _INLINE[1:]:
        joined = pat.sub(repl, joined)
    return joined


def convert(md: str) -> str:
    lines = md.split("\n")
    out: list[str] = []
    i, n = 0, len(lines)
    in_list = False

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    while i < n:
        line = lines[i]

        if line.startswith("```"):                      # fenced code
            close_list()
            i += 1
            body = []
            while i < n and not lines[i].startswith("```"):
                body.append(lines[i])
                i += 1
            i += 1
            out.append("<pre><code>" + html.escape("\n".join(body)) + "</code></pre>")
            continue

        if re.match(r"^\s*\|", line) and i + 1 < n and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]):
            close_list()                                # table
            def cells(row: str) -> list[str]:
                return [c.strip() for c in row.strip().strip("|").split("|")]
            head = cells(line)
            i += 2
            out.append("<table><thead><tr>"
                       + "".join(f"<th>{inline(c)}</th>" for c in head)
                       + "</tr></thead><tbody>")
            while i < n and re.match(r"^\s*\|", lines[i]):
                out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells(lines[i])) + "</tr>")
                i += 1
            out.append("</tbody></table>")
            continue

        if re.match(r"^---+\s*$", line):
            close_list()
            out.append("<hr>")
            i += 1
            continue

        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            close_list()
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{inline(m.group(2))}</h{lvl}>")
            i += 1
            continue

        m = re.match(r"^\s*[-*]\s+(.*)$", line)
        if m:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(m.group(1))}</li>")
            i += 1
            continue

        if not line.strip():
            close_list()
            i += 1
            continue

        para = []                                       # paragraph: join soft wraps
        while i < n and lines[i].strip() and not re.match(
            r"^(#{1,4}\s|```|---+\s*$|\s*\|)", lines[i]
        ) and not re.match(r"^\s*[-*]\s+", lines[i]):
            chunk = lines[i].strip()
            if lines[i].endswith("  "):                 # markdown hard break
                chunk += BREAK                          # a real <br> would be escaped
            para.append(chunk)
            i += 1
        close_list()
        out.append("<p>" + inline(" ".join(para)).replace(BREAK, "<br>") + "</p>")

    close_list()
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>Application Security Assessment</title><style>{CSS}</style>"
        "</head><body>" + "\n".join(out) + "</body></html>"
    )


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as fh:
        markup = convert(fh.read())
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(markup)
    print(f"wrote {dst} ({len(markup):,} bytes)")
