<!-- Rendered into the profile README at github.com/BU1lDR by
     BU1lDR/BU1lDR/tools/build_readme.py, on the hour and on dispatch.
     Format: "# <display name> — <heading tail>", a one-line meta row, then at most
     two short paragraphs. Placeholders filled from the GitHub API: {license}
     {version} {live} {description}. Keep it brief; the detail belongs in README.md
     and decisions.md, which CI holds to the code. -->

# secscan — SCA, SAST and DAST in one Python CLI

{license} · {version} · Python · asyncio · httpx · pytest

Scans a codebase or a live site: dependency CVEs from OSV.dev, regex SAST for dangerous sinks and hardcoded secrets, passive DAST over TLS, headers, cookies and exposed files, plus opt-in active checks behind an authorization gate. Exit code `3` keeps "could not look" apart from "found nothing".

CI rehearses the active tier on every push against a deliberately flawed loopback site, judged from the server's own request log, then repeats the scan with authorization withheld and requires that no probe reaches the wire. The suite also runs with sockets blocked, and a weekly job asks OSV whether the project's own dependency floors are vulnerable.
