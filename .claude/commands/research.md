---
description: Verify a dependency, crate API or OS API against live docs before using it, and record the result in docs/DEPENDENCIES.md
---
Invoke the `research-verifier` subagent for: **$ARGUMENTS**

Instructions for the agent (§D.1 rule 4): never trust memory for versions or APIs. Verify against crates.io (`https://crates.io/api/v1/crates/<name>`), the actual crate source (download `https://static.crates.io/crates/<name>/<name>-<version>.crate` to `/tmp/crates-src/`, extract, read `src/` and `examples/`), docs.rs, and vendor documentation for OS APIs. Produce a sourced note (every claim has a URL or a source path) under `docs/research/<topic>.md` and add or update the row(s) in `docs/DEPENDENCIES.md` with: crate/API → exact version → cargo features → why → build requirements (system libs, bindgen, cmake) → verified-on date → source. Flag anything that cannot compile on the current machine and must be verified in CI or on another device.

Report back the exact pins and any gotchas that change how the code should be written.
