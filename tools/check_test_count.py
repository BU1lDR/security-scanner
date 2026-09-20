"""Assert the test count quoted in decisions.md and on the repo's own front page
is the count pytest collects.

This exists because that number was wrong three times in a row, and each time the
thing that made it wrong was adding tests — the most routine change there is. A
figure that goes stale every time the project improves is a figure nobody can
maintain by remembering to, so it is checked instead. (Four times, counting the
commit that added this file: the inert-span guard took the suite 357 -> 367 and
this script is what caught it, which is the check earning its keep on its first
real outing rather than a hypothetical.)

Five times, counting the one that prompted the second check below. The GitHub
repository description — the sentence under the repo name, and the only copy a
visitor reads before they read anything else — sat at "353 tests" through two
increments while every checked copy moved. It went stale precisely because this
script's own error message enumerated every location it knew about and that one
was not among them: the list was the map, and the map was missing a country.

So the description is now checked too, which costs this script the property it
used to advertise: it needs the network. That is a real loss and worth naming.
The tradeoff is that the alternative was to keep an unchecked number in the most
widely read place it appears, and this repo's position on unchecked numbers is
already recorded — see the message printed on failure.

Run from the repo root: ``python tools/check_test_count.py``. Exits non-zero with
both numbers and the exact ``gh repo edit`` command for whichever copy disagreed;
both copies are checked on every run, so two stale numbers are two lines of output
rather than two round trips. CI runs it.

When the API cannot be reached it says so, in those words, rather than reporting
agreement — D42 applied to this script instead of to the scanner: "we found
nothing" and "we could not look" must not produce the same output. Under
GITHUB_ACTIONS that state also exits non-zero, because a check that quietly skips
itself in CI is precisely the green tick over nothing that this file exists to
prevent. Run by hand it only reports, so a clone with no token still gets the
decisions.md check rather than a wall.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "decisions.md"

API = "https://api.github.com/repos/{slug}"
TIMEOUT = 15

# "... three report formats and 357 tests." Captures the digits only. Used against
# decisions.md and against the repo description, which quote the figure the same way.
QUOTED = re.compile(r"\b(\d+) tests\b")

# pytest's own summary line, e.g. "357 tests collected in 0.31s". "test" is
# singular when there is exactly one, and there is an "errors" variant; only the
# plain success shape is accepted, so a collection error fails loudly rather than
# matching zero and comparing it to something.
COLLECTED = re.compile(r"^(\d+) tests? collected\b", re.MULTILINE)

EXTERNAL_COPIES = (
    "One copy of this figure lives outside this repo and CI here cannot reach\n"
    "it: the portfolio's assets/resume.src.html. Update it and rebuild the PDF\n"
    "(node tools/build-resume.js), which checks the PDF against the source.\n"
    "\n"
    "There used to be two more, in the portfolio's js/data.js and the profile\n"
    "README. They were deleted rather than synced, because a number nobody can\n"
    "check is worse than no number. Do not add them back."
)


def collected_count() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--collect-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    match = COLLECTED.search(proc.stdout)
    if proc.returncode != 0 or match is None:
        sys.stderr.write(proc.stdout[-2000:] + proc.stderr[-2000:])
        raise SystemExit(
            "could not read a collected-test count from pytest "
            f"(exit {proc.returncode}); see the output above"
        )
    return int(match.group(1))


def repo_slug() -> str | None:
    """owner/repo for the checkout, or None if it cannot be established.

    GITHUB_REPOSITORY first because in Actions it is authoritative and needs no
    subprocess. The remote is the fallback so a hand run works, and so a fork
    checks its own description rather than this one's — the figure is wrong or
    right per repository, and hardcoding the slug would have every fork assert
    against a page its owner cannot edit.
    """
    from_env = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if from_env.count("/") == 1:
        return from_env

    proc = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    url = proc.stdout.strip().removesuffix(".git")
    # https://github.com/owner/repo and git@github.com:owner/repo both reduce to
    # the last two path-ish segments; anything else is not a GitHub remote.
    parts = re.split(r"[/:]", url)
    if len(parts) < 2 or "github.com" not in url:
        return None
    return "/".join(parts[-2:])


def description_count(slug: str) -> tuple[int | None, str, str | None]:
    """(count, description, error). count is None when the description quotes no figure.

    The description comes back alongside the count because the fix for a stale one
    is a whole new description, not a patch: `gh repo edit` takes the replacement
    string entire. Having it here means the failure message can print the exact
    command rather than a sed expression the reader has to trust.

    The description is public, so the token is an optimisation: authenticated
    calls get the 5000/hour limit instead of 60/hour shared across everything
    else leaving that runner's IP, which is the difference between this check
    being reliable in CI and being reliable most of the time.
    """
    request = urllib.request.Request(
        API.format(slug=slug),
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            # The API rejects requests without one, and a named agent is the
            # courtesy the scanner's own USER_AGENT exists to extend.
            "User-Agent": f"secscan-check-test-count (+https://github.com/{slug})",
        },
    )
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    # One retry, and only for the failures that are plausibly the network rather
    # than the answer: a 5xx or a dropped connection. This gates commits, so a
    # transient blip must not redden a pull request that did not cause it — the
    # objection tools/check_floors.py raises against putting a network check on
    # push. A 404 or a 403 is not retried, because repeating the question does not
    # change a refusal, and a rate-limit 403 in particular deserves to be read.
    last: str | None = None
    for attempt in range(2):
        if attempt:
            time.sleep(2)
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            # First, because HTTPError is a URLError is an OSError: reversing these
            # two clauses would read every status code as a network failure.
            last = f"HTTP {exc.code} from the GitHub API for {slug}"
            if exc.code < 500:
                return None, "", last
        except (OSError, http.client.HTTPException) as exc:
            # OSError, not URLError, because URLError does not mean "the network
            # failed" — it means urlopen wrapped the failure, which it only does
            # before the response starts. Once bytes are arriving a dropped
            # connection surfaces as ConnectionResetError or http.client's
            # IncompleteRead, so the comment above promising a retry on "a dropped
            # connection" was describing a traceback. HTTPException is the one
            # family here that is not an OSError at all.
            reason = getattr(exc, "reason", exc) or exc.__class__.__name__
            last = f"could not reach the GitHub API for {slug}: {reason}"
        except json.JSONDecodeError as exc:
            return None, "", f"the GitHub API returned something that is not JSON: {exc}"
        else:
            break
    else:
        return None, "", f"{last} (retried once)"

    description = payload.get("description") or ""
    quoted = QUOTED.search(description)
    return (int(quoted.group(1)) if quoted else None), description, None


def check_doc(actual: int) -> bool:
    """Compare every figure decisions.md quotes, not the first one.

    finditer rather than search. The file quotes the count once today, which is
    what made search look sufficient, and nothing stops the next paragraph about
    the suite from quoting it again — the sibling project managed exactly that: the
    same commit that added its version of this check added a README paragraph
    explaining the check, which quoted the figure a second time, four lines below
    the copy the check corrects. A loop that stops at the first match would have
    fixed one copy and certified the other in the same breath.
    """
    text = DOC.read_text(encoding="utf-8")

    quoted = [
        (text[: match.start()].count("\n") + 1, int(match.group(1)))
        for match in QUOTED.finditer(text)
    ]

    if not quoted:
        print(
            f"no 'N tests' figure found in {DOC.name} at all. Either the wording\n"
            f"changed, in which case fix QUOTED, or the sentence was deleted — and\n"
            f"this check now passes by not looking, which is worse than the drift it\n"
            f"exists to catch."
        )
        return False

    stale = [item for item in quoted if item[1] != actual]
    if not stale:
        where = ", ".join(f"line {line_no}" for line_no, _ in quoted)
        print(
            f"{DOC.name} says {actual} tests at {where}; pytest collects {actual}. "
            f"Agreed."
        )
        return True

    print(f"pytest collects {actual} tests. {DOC.name} disagrees:")
    for line_no, claimed in stale:
        print(f"  {DOC.name}:{line_no} claims {claimed}")
    print(
        f"Update {'that line' if len(stale) == 1 else 'all of them'}.\n"
        f"\n" + EXTERNAL_COPIES
    )
    return False


def check_description(actual: int) -> bool:
    in_ci = os.environ.get("GITHUB_ACTIONS") == "true"

    slug = repo_slug()
    if slug is None:
        print(
            "could not work out which GitHub repository this checkout is, so the\n"
            "repo description went unchecked (no GITHUB_REPOSITORY and no github.com\n"
            "origin remote)."
        )
        return not in_ci

    claimed, description, error = description_count(slug)
    if error is not None:
        print(
            f"the repo description went unchecked: {error}.\n"
            f"decisions.md was still checked. Re-run with a network, or see\n"
            f"https://github.com/{slug} and compare the sentence under the repo name."
        )
        return not in_ci

    if claimed is None:
        print(
            f"{slug}'s description quotes no test count, so there is nothing there\n"
            f"to go stale. Nothing to do."
        )
        return True

    if claimed == actual:
        print(f"{slug}'s description says {claimed} tests; pytest collects {actual}. Agreed.")
        return True

    # count=1 so only the figure that was compared is rewritten; a description
    # that somehow quotes two counts should be looked at by a person, not
    # silently normalised by a suggestion this script printed.
    corrected = QUOTED.sub(f"{actual} tests", description, count=1)
    print(
        f"{slug}'s description claims {claimed} tests; pytest collects {actual}.\n"
        f"It is the first sentence a visitor reads and it is the one copy no commit\n"
        f"can fix, which is why it stayed at 353 while everything else moved. Run:\n"
        f"\n"
        f"  gh repo edit {slug} --description {shlex.quote(corrected)}\n"
        f"\n" + EXTERNAL_COPIES
    )
    return False


def main() -> int:
    actual = collected_count()
    # Both checks run before either verdict is returned, so two stale copies are
    # one run's output rather than two. `and` would short-circuit the second.
    doc_ok = check_doc(actual)
    description_ok = check_description(actual)
    return 0 if doc_ok and description_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
