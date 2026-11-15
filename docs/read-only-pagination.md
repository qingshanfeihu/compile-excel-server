# Read-only terminal pagination

This task branches from `ed89f6c`; the existing uncommitted `gw-pass-sessions` worktree is preserved. Only the terminal frame reader and its synthetic tests change. Pager continuation sends a space only for a complete marker at the buffer tail. It never enters configuration mode. UTF-8 decoding spans chunks; command wire text remains available separately as `raw_output`.

Validation: `python3 -m pytest -q tests/gateway/test_pagination_readonly.py` passed 4 tests. Before implementation, the three protocol tests failed because the frame reader lacked raw capture and pagination. The existing gateway suite could not collect with the available Python 3.9 because its configuration imports `tomllib`; no dependencies or runtime were installed. No real device or deployment test ran.

Further validation located an existing uv-managed Python 3.12. An offline temporary environment using the declared requirements installed from cache, without changing the dependency files. Collection of the existing probe suite then stopped because the isolated checkout has no generated `gateway/vendor/cex_core`. The live checkout's generated vendor contains internal assets by the vendoring contract, so it was not copied or imported into this development tree. The four standalone terminal tests remain passed; the existing probe suite remains unrun, not passed.
