# Historical AiReverse reference scripts

These Python copies preserve the original algorithms for comparison and manual compatibility. REA does not call them in its normal workflow. The active workflow, configuration decoding, protocol decoding, traversal, case checking and report generation use TypeScript under `src/domain/mobileGame`, `src/application/mobileGame` and `src/mobileGame`.

The only bundled Python provider helper used by REA is `internal/providers/unity_resources.py`, which adapts the bring-your-own UnityPy engine. It owns format conversion only; REA owns source selection, budgets, supervision, case outputs and Evidence. pycdc and ILSpy are also bring-your-own engines selected explicitly through typed resource options.

Do not run legacy scripts that install tools automatically as part of REA setup or analysis. See `docs/mobile-game-integration.md` for public CLI/MCP operations.
