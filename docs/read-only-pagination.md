# Read-only terminal pagination

This task branches from `ed89f6c`; the existing uncommitted `gw-pass-sessions` worktree is preserved. Only the terminal frame reader and its synthetic tests change. Pager continuation sends a space only for a complete marker at the buffer tail. It never enters configuration mode. UTF-8 decoding spans chunks; the helper keeps transient wire evidence internally; raw fields are excluded from the public probe reply.

Validation: `python3 -m pytest -q tests/gateway/test_pagination_readonly.py` passed 4 tests. Before implementation, the three protocol tests failed because the frame reader lacked raw capture and pagination. The existing gateway suite could not collect with the available Python 3.9 because its configuration imports `tomllib`; no dependencies or runtime were installed. No real device or deployment test ran.

Further validation located an existing uv-managed Python 3.12. An offline temporary environment using the declared requirements installed from cache, without changing the dependency files. Collection of the existing probe suite then stopped because the isolated checkout has no generated `gateway/vendor/cex_core`. The live checkout's generated vendor contains internal assets by the vendoring contract, so it was not copied or imported into this development tree. The four standalone terminal tests remain passed; the existing probe suite remains unrun, not passed.


## Review follow-up

The independent review at `a463b64` reproduced four protocol defects with red tests: colored prompt framing, split pager erase controls, EOF after a complete prompt, and a partial UTF-8 suffix after a prompt. A further red test found that an ANSI reset after a pager could incorrectly reuse an earlier prompt as completion. Another red test proved that incomplete login/enable/paging setup still allowed the probe command to be issued. These cases now preserve incomplete state or stop setup rather than inventing a completed observation.

The reader interprets complete ANSI CSI controls incrementally for its display view, retains incomplete sequences, and recognizes only two declared pager erase forms. It does not render a general terminal or infer device health from the display. Exact received command bytes are available only inside the helper as base64, with the decoded compatibility view labeled `utf-8-replace`; failed reads retain their received prefix. No new archive or raw retrieval route is introduced.

The review also found that the earlier `raw_output` addition bypassed `framework.probe`'s output-only scrub boundary. The public boundary now selects only the declared text/boolean fields, rejects malformed or missing public payloads, applies the existing scrub function to every public textual field, and leaves the caller's existing literal redaction in place. Raw text, base64, hashes and references are not public result fields. Raw command evidence is not durably archived by this change, which remains a limit for later byte-level historical verification. A real boundary-function component test failed against the pre-review source and now passes; it compiles only that function to avoid importing the unavailable vendor, and explicitly does not replace full integration testing.

Final validation:

- `python3 -m pytest -q tests/gateway/test_pagination_readonly.py`: 19 passed, 0 skipped, using synthetic channels/SSH only.
- Python 3.12 from the existing uv runtime, offline declared requirements, same target file: 19 passed, 0 skipped.
- The agent source parses under Python 3.8 grammar.
- `git diff --check`: passed.
- Python 3.12, offline declared requirements, `tests/gateway/test_probe.py`: collection error because generated `cex_core` is absent; no test ran in that command. No vendor, test assertion or runtime requirement was weakened to make it green.

No device login, real SSH, business-system request, deployment or source credential access occurred. The original dirty `gw-pass-sessions` worktree was not modified.
