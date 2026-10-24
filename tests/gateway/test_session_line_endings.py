"""会话证据必须保留 CRLF；读取、截尾与 JSON 往返都不能暗改匹配输入。"""

import json

from gateway.framework import case_sessions, tail_lines


def test_session_text_preserves_crlf_and_lone_carriage_returns(tmp_path):
    aid = "202610090000000001"
    folder = tmp_path / aid
    folder.mkdir()
    raw = b"prompt> inspect\r\nREADY\r\nprogress\rnext\r\n"
    (folder / "client.txt").write_bytes(raw)
    result = case_sessions(tmp_path, aid)
    assert json.loads(json.dumps(result))["client.txt"].encode() == raw


def test_tail_preserves_line_endings_of_retained_lines():
    text = "discard this line\r\nREADY\r\nDONE\r\n"
    assert tail_lines(text, 18) == "READY\r\nDONE\r\n"
