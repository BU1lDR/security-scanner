# Sample report build

Builds `docs/sample-report.pdf` — the PyGoat assessment sent to prospects as a work
sample — from `sample-report-pygoat.md`.

These scripts lived outside version control until now, in a directory excluded by
`.git/info/exclude`. They are here so the PDF stays reproducible rather than being a
binary nobody can regenerate.

## Files

| File | What it does |
|---|---|
| `sample-report-pygoat.md` | The report itself. Source of truth; edit this, never the HTML or PDF. |
| `md2html.py` | Markdown → HTML. Deliberately not a general Markdown implementation: it handles only the constructs the report uses, and carries the print CSS (A4, page-break rules for tables and code blocks). No dependencies. |
| `fix_hard_breaks.py` | One-off repair. The cover block and each finding's `Location` / `Route` lines were written one per line without trailing double spaces, so Markdown collapsed them into a run-on paragraph. Dry run by default; `--apply` writes. |
| `build_finding_png.py` | Renders a single finding as a PNG for use as LinkedIn media. Takes a start line, end line and output name, and refuses if the start line is not a `## F-` heading. Needs Pillow. |

Both `fix_hard_breaks.py` and `build_finding_png.py` resolve the markdown relative to
their own directory, so keep the four files together.

## Rebuilding the PDF

Two steps, from this directory:

```sh
python md2html.py sample-report-pygoat.md sample-report-pygoat.html

"/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" \
  --headless=new --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="<abs path>/sample-report.pdf" \
  "file:///<abs path>/sample-report-pygoat.html"
```

Edge needs absolute paths for both arguments, and `--no-pdf-header-footer` matters — without
it every page gets a URL and a date in the margins.

This chain reproduces the committed `docs/sample-report.pdf` to the byte **except for eight
bytes**, which are the two timestamps: Skia stamps `/CreationDate` and `/ModDate` from the
wall clock at one-second resolution, so no two runs can agree on them unless they happen in
the same second. Everything else is identical — same 643,442-byte length, same 33 pages, and
overwriting one file's timestamp with the other's makes the two compare equal:

```sh
python - <<'EOF'
import re
new = open('out.pdf','rb').read()
old = open('docs/sample-report.pdf','rb').read()
stamp = re.search(rb"D:\d{14}\+00'00'", old).group(0)
print(re.sub(rb"D:\d{14}\+00'00'", stamp, new) == old)   # True
EOF
```

This said "reproduces … byte for byte" until it was actually run twice and compared. It does
not, it cannot, and "byte for byte" is a claim with a single unambiguous meaning — which is
exactly why it is worth either measuring or not making. The eight bytes are the whole of the
difference, and saying so is both true and more informative than the round version was.

The intermediate HTML is not tracked; it is regenerated on every build.

## A note on the target

The report assesses [PyGoat](https://github.com/adeyosemanputra/pygoat), a deliberately
insecure Django training application. No client is being anonymised, and the report says so
on its first page. That is the point: it shows the output format on a target anyone can
verify, with nothing redacted.
