# `agy-golden-stack` — Unified In-Process P10..P50 AgentOps & Hook Multiplexer Bus

`agy-golden-stack` unites the 5 core AGY engineering modules into a single-process, sub-millisecond (`<1ms`) in-memory execution bus (`GoldenStackBus`).

## Architecture (`P10 -> P20 -> P30 -> P40 -> P50`)

| Priority Slot | Name | Responsibility |
|---|---|---|
| **`P10`** | `runtime_doctor` | Heals stale `.git/index.lock` deadlocks, audits MCP `<64`-char tool names, and coerces unsafe 64-bit JS integers (`> 9007199254740991`). |
| **`P20`** | `brain_memory` | Validates `[Label](conversation://<uuid>)` cross-session links and flags bare links. |
| **`P30`** | `iso9000_gate` | Enforces Agile V role separation (`implementer` blocked from modifying `tests/`, `test-designer` blocked from modifying `src/`) and verifies locked test SHA-256 hashes. |
| **`P40`** | `lsrpc_plugin` | Validates native plugin manifests (`plugin.json`), root `hooks.json` placement, and frontmatter-free `rules/AGENTS.md`. |
| **`P50`** | `oss_release_gate` | Intercepts `PreToolUse` `git push` / `gh release create` commands and blocks publication if any of the 5 Open-Source Release Gates fail. |

## Quick Start

```bash
# 1. Inspect registered P10..P50 slots
python -m agy_golden_stack.cli status --json

# 2. Benchmark 5-slot in-process dispatch latency
python -m agy_golden_stack.cli benchmark --iterations 50 --json

# 3. Audit or consolidate competing hooks.json across installed plugins
python -m agy_golden_stack.cli audit-hooks --json
```

## License

MIT License — Copyright (c) 2026 AGY Golden Stack Contributors
