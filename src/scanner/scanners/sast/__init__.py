"""The SAST scanner (``sast``): regex pattern matching over local source code.

Static Application Security Testing, v1 = *pattern* SAST: it reads source files
and flags lines matching a curated rule pack — dangerous sinks (``sast.sink.*``,
e.g. ``eval``, ``pickle.loads``, ``shell=True``) and hardcoded secrets
(``sast.secret.*``, e.g. AWS keys, private keys, high-entropy API tokens).

It is deliberately *not* dataflow/taint analysis (deferred): a match means "this
pattern is present here," not "this is reachable by an attacker" — hence sink
findings are FIRM and looser secret heuristics are TENTATIVE, leaving the human
to judge exploitability. Secret matches are redacted at construction: the raw
value never reaches a Finding (contract §4, decisions.md D10).
"""
