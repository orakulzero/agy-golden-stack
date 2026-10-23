---
name: agy-golden-stack
description: >-
  Unified In-Process P10..P50 AgentOps & Hook Multiplexer Bus (GoldenStackBus)
  uniting Runtime Doctor (P10), Brain Memory (P20), ISO 9001 Agile V Self-Grading
  Bias Gate (P30), LSRPC Plugin Validator (P40), and 5-Gate OSS Release Auditor (P50).
---

# Unified Golden Stack In-Process Bus (`agy-golden-stack`)

Unites the 5 core AGY engineering modules into a single-process in-memory execution
bus (`GoldenStackBus`) with sub-millisecond (`<1ms`) dispatch and re-entrancy loop protection.

## Priority Slots (`P10 -> P50`)

1. **`P10` (`runtime_doctor`)**: Heals stale `.git/index.lock` deadlocks, audits MCP `<64`-char tool names, and coerces overflowing 64-bit integer IDs (`> 9007199254740991`).
2. **`P20` (`brain_memory`)**: Validates cross-session links (`[Label](conversation://<uuid>)`) and flags bare links.
3. **`P30` (`iso9000_gate`)**: Enforces Agile V role separation (`implementer` blocked from modifying `tests/`, `test-designer` blocked from modifying `src/`) and verifies SHA-256 hashes of locked test files.
4. **`P40` (`lsrpc_plugin`)**: Audits native plugin bundles (`plugin.json`, root `hooks.json`, frontmatter-free `rules/AGENTS.md`).
5. **`P50` (`oss_release_gate`)**: Intercepts `PreToolUse` `git push` / `gh release create` commands and blocks release if any of the 5 Open-Source Release Gates fail.

## CLI Usage

```bash
# Inspect registered P10..P50 slots
python -m agy_golden_stack.cli status --json

# Dispatch a lifecycle event through the in-process bus
python -m agy_golden_stack.cli dispatch PreToolUse --payload '{"tool_name":"write_file","role":"implementer","target_path":"src/main.py"}' --json

# Benchmark 5-slot in-memory latency
python -m agy_golden_stack.cli benchmark --iterations 50 --json

# Audit or consolidate competing hooks.json across installed plugins
python -m agy_golden_stack.cli audit-hooks --json
```
