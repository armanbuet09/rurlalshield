# Repository workflow

- After each completed change to source, tests or operational documentation, run the relevant checks and create a local Git commit.
- Exclude paper sources, diagrams, PDF exports and paper-only build tools from commits. Keep paper/ and output/pdf/ local, including changes to previously tracked paper files, unless the user explicitly asks to include them.
- Keep credentials, private research evidence, local AWS configuration, build caches and temporary renderings out of commits.
- Do not push commits unless the user asks.
- Preserve the frozen five-day non-AI pilot and follow docs/NONAI_PILOT.md, docs/NONAI_CLOSEOUT.md and docs/LOCAL_EVIDENCE.md for research operations.
