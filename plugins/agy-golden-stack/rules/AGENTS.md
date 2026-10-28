# AGY Golden Stack Unified Ecosystem & Zero-Loss Context Rules (`v2.0.0`)

1. **Hygiene & Routing**: Maintain 100% English-only repository source/docs/commits, dynamic relative paths, DPAPI secret quarantine, and single-process `GoldenStackBus` (`P10..P50`) hook routing.
2. **Agile V Role Separation (`P30`)**: `test-designer` authors locked tests in `tests/`; `implementer` authors code in `src/` without modifying `tests/`.
3. **Domain Invariants**:
   - *Computer Use*: Normalize coordinates to `[0, 1000] x [0, 1000]`, preserve `(0, 0)` fail-safe abort, verify GUI transitions via 64-bit dHash `VisualActionOracle` (`Hamming >= 2` -> `[FACT]`).
   - *ESKD Vision*: Rasterize at `300 DPI` (`zoom = 4.1666667`), clamp 27-class YOLO bboxes to `[0.0, 1.0]`, lock `mosaic=0.0, fliplr=0.0, flipud=0.0, degrees=0.0`.
   - *PE Reversing*: Verify `MZ` (`0x5A4D`) & `PE\0\0`, flag section Shannon entropy `>= 7.0`, map IAT capabilities.
   - *Brain & LSRPC*: Format conversation links as `[<label>](conversation://<conv_id>)`; compact `GetAllPlugins`; key mutations on plugin `dir`.
4. **Zero-Loss Context & Latency Optimization**:
   - *SSE Stream Chunking Guard*: Keep every `write_file` or `edit_file` call `<= 180` lines (`<= 3,500` output tokens); use modular files or sequential `write_file(..., Append=True)` to prevent 240s SSE `EOF` timeouts.
   - *Read Batching Guard*: Read up to `800` lines per `read_file` call or issue parallel `read_file` calls in one turn; never chain sequential `50-150` line reads.
   - *Subagent Context Firewall*: Delegate reading external reference files (`>500` lines), prior session transcripts, or large HTML/code templates to `invoke_subagent(TypeName="research")` or targeted Python AST/regex scripts so raw dumps never bloat the primary context window.
   - *Multimodal Image Isolation*: Do not load `>2` binary PNGs via `read_file` into the main conversation; inspect image batches (`contact_sheet.png`, `image1..N.png`) via a `research` subagent or Python geometry script and return a compact text summary.
   - *Two-Tier Memory Anchor*: Persist exact task invariants (variant parameters, numerical results, file map, `REQ-*` status) in `PROGRESS.md` so `/compact` at `>120K` tokens restores `5-8s` step latency with zero loss of context.
