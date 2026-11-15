# Read-only terminal pagination

This task branches from `ed89f6c`; the existing uncommitted `gw-pass-sessions` worktree is preserved. Only the terminal frame reader and its synthetic tests change. Pager continuation sends a space only for a complete marker at the buffer tail. It never enters configuration mode. UTF-8 decoding spans chunks; command wire text remains available separately as `raw_output`.

Validation: `python3 -m pytest -q tests/gateway/test_pagination_readonly.py` passed 4 tests. Before implementation, the three protocol tests failed because the frame reader lacked raw capture and pagination. The existing gateway suite could not collect with the available Python 3.9 because its configuration imports `tomllib`; no dependencies or runtime were installed. No real device or deployment test ran.
