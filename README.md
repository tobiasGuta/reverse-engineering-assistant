# ReVa Reverse-Engineering Experiments

This repository tracks our experimental, general-purpose extensions for [ReVa](https://github.com/cyberkaida/reverse-engineering-assistant).

The repository was created independently rather than as a GitHub fork with upstream history, so we use it as a development/patch repository against a pinned upstream ReVa revision.

Current work lives on feature branches. The first branch is:

- `feat/static-analysis-expansion` — generic, read-only program intelligence, CFG, P-code, and source-metadata capabilities.

The expansion is reviewed against upstream ReVa commit `01a154a8edf233b02a0e7707e2ff5933893c6d53`.

The MCP primitive layer should expose reverse-engineering facts and operations, not challenge-specific flag/password/malware heuristics.
