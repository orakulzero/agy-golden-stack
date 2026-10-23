# AGY Golden Stack Unified Bus Operational Rules

1. Maintain 100% English-only source, documentation, and commit messages.
2. Enforce dynamic relative paths and never commit personal credentials or local user paths.
3. Route all lifecycle hooks through the single-process `GoldenStackBus` (`P10 -> P20 -> P30 -> P40 -> P50`) to eliminate multi-process spawn overhead.
4. Enforce strict Agile V role separation (`P30`): `implementer` must never modify locked `tests/` files, and `test-designer` must never modify `src/` files.
